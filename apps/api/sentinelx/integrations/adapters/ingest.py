"""Security telemetry ingest adapters.

Each adapter parses a vendor log format into the normalized Event schema.
Configuration is via environment variables pointing at log file paths; when
unset the adapter reports NOT_INSTALLED gracefully.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from ..base import NormalizedEvent, ToolAdapter, ToolNotInstalled

EVENT_META = {
    "suricata": "SURICATA_EVE_PATH",
    "wazuh": "WAZUH_ALERTS_PATH",
    "zeek": "ZEEK_LOG_DIR",
}


class _FileAdapter(ToolAdapter):
    category = "ingest"
    env_var = ""

    def health_check(self) -> dict[str, Any]:
        path = os.environ.get(self.env_var, "")
        ok = bool(path) and Path(path).exists()
        return {
            "name": self.name,
            "installed": ok,
            "version": None,
            "health": "OK" if ok else "NOT_INSTALLED",
        }

    def _source_path(self) -> Path:
        path = os.environ.get(self.env_var, "")
        if not path or not Path(path).exists():
            raise ToolNotInstalled(f"{self.name} source not configured ({self.env_var})")
        return Path(path)


class SuricataAdapter(_FileAdapter):
    name = "suricata"
    env_var = "SURICATA_EVE_PATH"
    description = "Suricata EVE JSON alert ingestion"

    def execute(self, request: dict[str, Any]) -> str:
        path = self._source_path()
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        start = int(request["params"].get("start_line", 0))
        limit = int(request["params"].get("limit", 5000))
        return "\n".join(lines[start : start + limit])

    def parse_output(self, raw: str) -> list[NormalizedEvent]:
        events: list[NormalizedEvent] = []
        for line in raw.splitlines():
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if rec.get("event_type") != "alert":
                continue
            alert = rec.get("alert", {})
            events.append(
                NormalizedEvent(
                    event_type=f"suricata:{alert.get('signature_id')}:{alert.get('signature', 'alert')[:60]}",
                    severity=_map_suricata_severity(alert.get("severity")),
                    asset_ip=rec.get("dest_ip"),
                    metadata={
                        "src_ip": rec.get("src_ip"),
                        "dest_port": rec.get("dest_port"),
                        "proto": rec.get("proto"),
                        "category": alert.get("category"),
                        "rule": alert.get("signature"),
                        "engine": "suricata",
                    },
                )
            )
        return events

    def normalize_result(self, parsed: list[NormalizedEvent]) -> dict[str, Any]:
        return {"assets": [], "services": [], "findings": [], "events": parsed}


class ZeekAdapter(_FileAdapter):
    name = "zeek"
    env_var = "ZEEK_LOG_DIR"
    description = "Zeek conn.log ingestion"

    def _conn_path(self) -> Path:
        d = self._source_path()
        return d / "conn.log"

    def execute(self, request: dict[str, Any]) -> str:
        path = self._conn_path()
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        start = int(request["params"].get("start_line", 0))
        limit = int(request["params"].get("limit", 5000))
        return "\n".join(lines[start : start + limit])

    def parse_output(self, raw: str) -> list[NormalizedEvent]:
        events: list[NormalizedEvent] = []
        headers: dict[str, int] = {}
        for line in raw.splitlines():
            if line.startswith("#separator"):
                continue
            if line.startswith("#fields"):
                headers = {f: i for i, f in enumerate(line.split()[1:])}
                continue
            if line.startswith("#"):
                continue
            parts = line.split("\t")
            if not headers or len(parts) < len(headers):
                continue
            def g(name: str) -> str:
                idx = headers.get(name)
                return parts[idx] if idx is not None and idx < len(parts) else ""

            state = g("conn_state")
            if state not in {"S0", "S1", "SF", "REJ", "RSTO", "RSTR", "OTH"}:
                continue
            events.append(
                NormalizedEvent(
                    event_type=f"zeek:conn:{state}",
                    severity="low" if state in {"SF", "S1"} else "medium",
                    asset_ip=g("id.orig_h"),
                    metadata={
                        "src_ip": g("id.orig_h"),
                        "src_port": g("id.orig_p"),
                        "dest_ip": g("id.resp_h"),
                        "dest_port": g("id.resp_p"),
                        "proto": g("proto"),
                        "service": g("service"),
                        "bytes": g("orig_bytes"),
                        "engine": "zeek",
                    },
                )
            )
        return events

    def normalize_result(self, parsed: list[NormalizedEvent]) -> dict[str, Any]:
        return {"assets": [], "services": [], "findings": [], "events": parsed}


class WazuhAdapter(_FileAdapter):
    name = "wazuh"
    env_var = "WAZUH_ALERTS_PATH"
    description = "Wazuh alerts.json ingestion"

    def execute(self, request: dict[str, Any]) -> str:
        path = self._source_path()
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        start = int(request["params"].get("start_line", 0))
        limit = int(request["params"].get("limit", 5000))
        return "\n".join(lines[start : start + limit])

    def parse_output(self, raw: str) -> list[NormalizedEvent]:
        events: list[NormalizedEvent] = []
        for line in raw.splitlines():
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            rule = rec.get("rule", {})
            events.append(
                NormalizedEvent(
                    event_type=f"wazuh:{rule.get('id')}:{rule.get('description', 'alert')[:60]}",
                    severity=_map_wazuh_level(rule.get("level", 3)),
                    asset_ip=rec.get("agent", {}).get("ip"),
                    metadata={
                        "agent": rec.get("agent", {}).get("name"),
                        "group": rec.get("groups", [None])[0] if rec.get("groups") else None,
                        "rule": rule.get("description"),
                        "level": rule.get("level"),
                        "data": rec.get("data", {}),
                        "engine": "wazuh",
                    },
                )
            )
        return events

    def normalize_result(self, parsed: list[NormalizedEvent]) -> dict[str, Any]:
        return {"assets": [], "services": [], "findings": [], "events": parsed}


def _map_suricata_severity(sev: Any) -> str:
    return {1: "critical", 2: "high", 3: "medium"}.get(sev, "low")


def _map_wazuh_level(level: int) -> str:
    if level >= 12:
        return "critical"
    if level >= 8:
        return "high"
    if level >= 5:
        return "medium"
    return "low"
