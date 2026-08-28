"""Live telemetry collection.

LAB HOSTS → JSONL log files (lab apps / sensor) → watcher → normalize →
event store → detection → incident.

The watcher tails configured JSONL sources (no manual file copying, no
restart to pick up new data) and pushes events through the same
`ingest_events` pipeline as every other source, so detection rules fire on
real telemetry.
"""
from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from ..config import settings
from ..db import SessionLocal
from ..integrations.base import NormalizedEvent
from ..models import Asset, Organization
from .events import ingest_events

logger = logging.getLogger(__name__)

# telemetry.py lives at <root>/apps/api/sentinelx/services/ → parents[4] is <root>
_PROJECT_ROOT = Path(__file__).resolve().parents[4]
DEFAULT_SOURCES = [
    _PROJECT_ROOT / "cyber-range" / "logs" / "lab-web.jsonl",
    _PROJECT_ROOT / "cyber-range" / "logs" / "lab-api.jsonl",
    _PROJECT_ROOT / "cyber-range" / "logs" / "sensor.jsonl",
]

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _source_paths() -> list[Path]:
    if settings.TELEMETRY_SOURCES.strip():
        return [Path(p.strip()) for p in settings.TELEMETRY_SOURCES.split(",") if p.strip()]
    return DEFAULT_SOURCES


def _org_id(db: Session) -> str | None:
    org = db.query(Organization).filter(Organization.slug == settings.TELEMETRY_ORG_SLUG).first()
    return org.id if org else None


def _resolve_asset_ip(db: Session, org_id: str, name: str | None) -> str | None:
    if not name:
        return None
    asset = (
        db.query(Asset)
        .filter(Asset.org_id == org_id, (Asset.name == name) | (Asset.dns_name == name))
        .first()
    )
    return asset.ip_address if asset and asset.ip_address else None


def _parse_line(line: str, db: Session, org_id: str) -> NormalizedEvent | None:
    try:
        rec = json.loads(line)
    except json.JSONDecodeError:
        return None
    event_type = rec.get("event_type")
    if not event_type:
        return None
    ts = None
    raw_ts = rec.get("ts") or rec.get("timestamp")
    if raw_ts:
        try:
            ts = datetime.fromisoformat(str(raw_ts).replace("Z", "+00:00"))
        except ValueError:
            ts = None
    severity = str(rec.get("severity", "low")).lower()
    if severity not in SEVERITY_ORDER:
        severity = "low"
    return NormalizedEvent(
        event_type=str(event_type)[:64],
        severity=severity,
        timestamp=ts,
        asset_ip=_resolve_asset_ip(db, org_id, rec.get("asset")),
        user=rec.get("user"),
        metadata={
            "source_line": str(rec.get("source", "lab-app")),
            "message": str(rec.get("message", ""))[:500],
            "asset_name": rec.get("asset"),
            "meta": rec.get("meta") or {},
        },
    )


def _read_new_lines(path: Path, offset: int) -> tuple[int, list[str]]:
    """Read lines appended since `offset`; returns (new_offset, lines)."""
    try:
        size = path.stat().st_size
    except OSError:
        return offset, []
    if size < offset:
        offset = 0  # file rotated/truncated
    if size == offset:
        return offset, []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        f.seek(offset)
        lines = f.read().splitlines()
    return size, lines


def ingest_source_now(db: Session, path: Path, offsets: dict[str, int]) -> int:
    """Ingest new lines from one source; returns count of persisted events."""
    if not path.exists():
        return 0
    key = str(path)
    new_offset, lines = _read_new_lines(path, offsets.get(key, 0))
    offsets[key] = new_offset
    if not lines:
        return 0

    org_id = _org_id(db)
    if org_id is None:
        logger.warning("telemetry: no org for slug=%s — dropping events", settings.TELEMETRY_ORG_SLUG)
        return 0

    events = []
    for line in lines:
        ne = _parse_line(line, db, org_id)
        if ne is not None:
            events.append(ne)
    if not events:
        return 0

    persisted, detections = ingest_events(db, org_id, events, source="lab-app", demo=False)
    if detections:
        logger.info("telemetry: %d events, %d detections", persisted, len(detections))
    return persisted


async def telemetry_watcher(stop_event: asyncio.Event | None = None, interval: float = 1.5) -> None:
    """Background task tailing JSONL telemetry sources (see main.lifespan)."""
    if not settings.TELEMETRY_ENABLED:
        logger.info("telemetry watcher disabled (TELEMETRY_ENABLED=false)")
        return
    sources = _source_paths()
    offsets: dict[str, int] = {}
    logger.info("telemetry watcher started: %s", ", ".join(str(s) for s in sources))
    while True:
        if stop_event is not None and stop_event.is_set():
            logger.info("telemetry watcher stopping")
            return
        db = SessionLocal()
        try:
            for path in sources:
                try:
                    ingest_source_now(db, path, offsets)
                except Exception:  # noqa: BLE001 — never kill the watcher
                    logger.exception("telemetry: failed ingesting %s", path)
        finally:
            db.close()
        await asyncio.sleep(interval)
