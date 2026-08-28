"""SIEM event pipeline + detection engine.

SENSOR → INGEST → NORMALIZE → ENRICH → CORRELATE → DETECT → INCIDENT

Detection layers: signature, threshold, correlation (multi-event). AI is an
additional layer, never the only one.
"""
from __future__ import annotations

import asyncio
import hashlib
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy.orm import Session

from ..models import Asset, DetectionRule, Event, Incident, IncidentTimelineEntry
from ..realtime import hub

DETECTED_STATUSES = {"OPEN", "INVESTIGATING", "CONTAINED"}


def event_dedup_hash(event_type: str, asset_id: str | None, ts: datetime, source: str) -> str:
    rounded = ts.replace(microsecond=0).isoformat()
    return hashlib.sha256(f"{event_type}|{asset_id}|{rounded}|{source}".encode()).hexdigest()[:32]


def ingest_events(
    db: Session,
    org_id: str,
    normalized_events: list[Any],
    source: str,
    demo: bool = False,
) -> tuple[int, list[dict[str, Any]]]:
    """Normalize + persist events, then run the detection engine.

    Returns (persisted_count, detections).
    """
    persisted = 0
    for ne in normalized_events:
        ts = ne.timestamp or datetime.now(timezone.utc)
        asset = None
        if ne.asset_ip:
            asset = db.query(Asset).filter(Asset.org_id == org_id, Asset.ip_address == ne.asset_ip).first()
        event_id = ne.metadata.get("event_id") or event_dedup_hash(ne.event_type, asset.id if asset else None, ts, source)
        exists = db.query(Event).filter(Event.org_id == org_id, Event.event_id == event_id).first()
        if exists:
            continue
        db.add(
            Event(
                org_id=org_id,
                event_id=event_id,
                timestamp=ts,
                source=source,
                asset_id=asset.id if asset else None,
                user_id=ne.user,
                event_type=ne.event_type,
                severity=ne.severity,
                metadata_json={**(ne.metadata or {}), "normalized_by": source},
                dedup_hash=event_id,
                demo=demo,
            )
        )
        persisted += 1
    db.commit()

    if persisted:
        new_events = (
            db.query(Event)
            .filter(Event.org_id == org_id)
            .order_by(Event.timestamp.desc())
            .limit(200)
            .all()
        )
        detections = run_detections(db, org_id, new_events)
        for ev in new_events:
            hub.publish_sync(
                org_id,
                "event_ingested",
                {"event_id": ev.id, "event_type": ev.event_type, "severity": ev.severity, "source": ev.source, "timestamp": ev.timestamp.isoformat()},
            )
        return persisted, detections
    return 0, []


# ---------- Detection rules ----------

def _as_aware(dt: datetime) -> datetime:
    """SQLite returns naive datetimes; normalize before comparing with aware now()."""
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _field_match(actual: dict[str, Any], expected: dict[str, Any]) -> bool:
    for key, value in expected.items():
        if actual.get(key) != value:
            return False
    return True


def _normalize_match(raw_match: Any) -> dict[str, Any]:
    """Tolerate rule authoring shorthand.

    Canonical form: {"type": "signature", "match": {"event_type": "..."}}.
    A string shorthand ("match": "event_type") is normalized to the dict form.
    The detection engine must never crash an ingest/job because a rule used an
    unexpected shape — unmatched rules are simply ignored.
    """
    if isinstance(raw_match, dict):
        return raw_match
    if isinstance(raw_match, str):
        return {"event_type": raw_match}
    return {}


def rule_matches(rule: DetectionRule, events: list[Event]) -> tuple[bool, list[Event]]:
    logic = rule.logic or {}
    rtype = logic.get("type", "signature")
    if rtype == "signature":
        match_fields = _normalize_match(logic.get("match", {}))
        matched = [e for e in events if _field_match(_event_fields(e), match_fields)]
        return bool(matched), matched[:20]
    if rtype == "threshold":
        match_fields = _normalize_match(logic.get("match", {}))
        threshold = int(logic.get("threshold", 5))
        window = int(logic.get("window_seconds", 300))
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=window)
        windowed = [e for e in events if _as_aware(e.timestamp) >= cutoff]
        counted: Counter = Counter()
        for e in windowed:
            if _field_match(_event_fields(e), match_fields):
                counted[(e.asset_id, e.event_type)] += 1
        matched = [
            e for e in windowed
            if _field_match(_event_fields(e), match_fields) and counted[(e.asset_id, e.event_type)] >= threshold
        ]
        return bool(matched), matched[:20]
    if rtype == "correlation":
        sequence = logic.get("sequence", [])
        idx = 0
        matched: list[Event] = []
        for e in sorted(events, key=lambda x: x.timestamp):
            if idx < len(sequence) and _field_match(_event_fields(e), sequence[idx]):
                matched.append(e)
                idx += 1
                if idx == len(sequence):
                    return True, matched
        return False, []
    return False, []


def _event_fields(e: Event) -> dict[str, Any]:
    return {
        "event_type": e.event_type,
        "severity": e.severity,
        "source": e.source,
        "asset_id": e.asset_id,
        "user_id": e.user_id,
        **{f"meta.{k}": v for k, v in (e.metadata_json or {}).items()},
    }


def run_detections(db: Session, org_id: str, events: list[Event]) -> list[dict[str, Any]]:
    """Evaluate DEPLOYED rules against recent events; create/update incidents."""
    rules = (
        db.query(DetectionRule)
        .filter(DetectionRule.org_id == org_id, DetectionRule.status == "DEPLOYED")
        .all()
    )
    detections: list[dict[str, Any]] = []
    for rule in rules:
        matched, matched_events = rule_matches(rule, events)
        if not matched:
            continue
        incident = _upsert_incident_for_rule(db, org_id, rule, matched_events)
        detections.append(
            {
                "rule_id": rule.rule_id,
                "rule_name": rule.name,
                "severity": rule.severity,
                "incident_id": incident.id if incident else None,
                "event_ids": [e.id for e in matched_events],
            }
        )
        hub.publish_sync(
            org_id,
            "detection",
            {"rule_id": rule.rule_id, "rule_name": rule.name, "severity": rule.severity, "incident_id": incident.id if incident else None},
        )
    return detections


def _upsert_incident_for_rule(db: Session, org_id: str, rule: DetectionRule, matched_events: list[Event]) -> Incident | None:
    from .incidents import add_timeline

    existing = (
        db.query(Incident)
        .filter(
            Incident.org_id == org_id,
            Incident.status.in_(DETECTED_STATUSES),
            Incident.detection_sources.contains([rule.rule_id]),
        )
        .first()
    )
    if existing:
        add_timeline(
            db,
            existing,
            timestamp=matched_events[-1].timestamp if matched_events else datetime.now(timezone.utc),
            event_id=matched_events[-1].event_id if matched_events else None,
            source=rule.source,
            kind="DETECTION",
            message=f"Rule '{rule.name}' matched again ({len(matched_events)} events)",
        )
        return existing

    incident = Incident(
        org_id=org_id,
        title=f"Detection: {rule.name}",
        severity=_rule_severity_to_incident(rule.severity),
        status="OPEN",
        description=rule.description or f"Generated by detection rule {rule.rule_id}",
        detection_sources=[rule.rule_id],
        attack_techniques=rule.mitre or [],
        affected_assets=[e.asset_id for e in matched_events if e.asset_id],
        affected_users=[e.user_id for e in matched_events if e.user_id],
    )
    db.add(incident)
    db.flush()
    add_timeline(
        db,
        incident,
        timestamp=matched_events[0].timestamp if matched_events else datetime.now(timezone.utc),
        event_id=matched_events[0].event_id if matched_events else None,
        source=rule.source,
        kind="DETECTION",
        message=f"Detection rule '{rule.name}' ({rule.rule_id}) fired on {len(matched_events)} events",
    )
    db.commit()
    return incident


def _rule_severity_to_incident(severity: str) -> str:
    return {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "info": "low"}.get(severity, "medium")


def proposed_rule_from_gap(db: Session, org_id: str, gap: dict[str, Any], created_by: str | None = None) -> DetectionRule:
    """Create a DRAFT detection rule from a purple-team gap (detection proposal)."""
    rule_id = "SIG-PROP-" + hashlib.sha1(gap.get("stage", "gap").encode()).hexdigest()[:8].upper()
    existing = db.query(DetectionRule).filter(DetectionRule.org_id == org_id, DetectionRule.rule_id == rule_id).first()
    if existing:
        return existing
    rule = DetectionRule(
        org_id=org_id,
        rule_id=rule_id,
        name=f"Proposed: detect {gap.get('stage', 'gap')} ({gap.get('technique', '')})",
        description=f"Detection proposal generated from purple-team gap at stage '{gap.get('stage')}'. "
                    f"Missing telemetry: {gap.get('missing_telemetry', 'unknown')}",
        source="CUSTOM",
        severity="high",
        mitre=[gap.get("technique", "")] if gap.get("technique") else [],
        logic={"type": "signature", "match": {"event_type": gap.get("suggested_event_type", "")}} if gap.get("suggested_event_type") else {"type": "signature", "match": {}},
        status="DRAFT",
        regression_test=True,
        created_by=created_by,
    )
    db.add(rule)
    db.commit()
    db.refresh(rule)
    return rule
