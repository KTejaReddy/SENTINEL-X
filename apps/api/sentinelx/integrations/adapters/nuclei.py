"""Nuclei adapter (JSONL output)."""
from __future__ import annotations

import json
from typing import Any

from ..base import NormalizedFinding, ToolAdapter, ToolNotInstalled, run_cli


class NucleiAdapter(ToolAdapter):
    name = "nuclei"
    category = "scanner"
    description = "Template-based vulnerability scanner (Nuclei JSONL parser)"

    def build_request(self, target: str, params: dict[str, Any]) -> dict[str, Any]:
        cmd = [
            self._binary_path(),
            "-u", target,
            "-jsonl", "-silent",
            "-severity", str(params.get("severity", "low,medium,high,critical")),
            "-rate-limit", str(params.get("rate_limit", 50)),
        ]
        if params.get("tags"):
            cmd += ["-tags", str(params["tags"])]
        if params.get("templates"):
            cmd += ["-t", str(params["templates"])]
        return {"cmd": cmd, "target": target, "params": params}

    def execute(self, request: dict[str, Any]) -> str:
        if not self._binary_available():
            raise ToolNotInstalled("nuclei is not installed")
        proc = run_cli(request["cmd"], timeout=int(request["params"].get("timeout", 600)))
        if proc.returncode not in (0, 1):
            raise ToolNotInstalled(f"nuclei failed: {proc.stderr[:400]}")
        return proc.stdout

    def parse_output(self, raw: str) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                results.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return results

    def normalize_result(self, parsed: list[dict[str, Any]]) -> dict[str, Any]:
        findings: list[NormalizedFinding] = []
        for item in parsed:
            info = item.get("info", {})
            severity = (info.get("severity") or "medium").upper()
            findings.append(
                NormalizedFinding(
                    title=info.get("name") or item.get("template-id", "nuclei finding"),
                    severity=severity,
                    description=info.get("description") or "",
                    cve=(info.get("classification") or {}).get("cve-id") or (info.get("cve") or None),
                    cwe=(info.get("classification") or {}).get("cwe-id") or None,
                    category=info.get("tags", [None])[0] if isinstance(info.get("tags"), list) and info.get("tags") else None,
                    endpoint=item.get("matched-at"),
                    cvss=(info.get("classification") or {}).get("cvss-score"),
                    remediation=(info.get("remediation") or ""),
                    confidence=0.8,
                    evidence={
                        "type": "nuclei_result",
                        "matched_at": item.get("matched-at"),
                        "template": item.get("template-id"),
                        "curl_command": item.get("curl-command"),
                        "response": (item.get("response") or "")[:2000],
                    },
                )
            )
        return {"assets": [], "services": [], "findings": findings, "events": []}
