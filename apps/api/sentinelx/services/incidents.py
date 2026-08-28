"""Incident management service."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy.orm import Session

from ..models import Incident, IncidentTimelineEntry


def add_timeline(
    db: Session,
    incident: Incident,
    *,
    timestamp: datetime | None = None,
    event_id: Optional[str] = None,
    source: Optional[str] = None,
    kind: str = "OBSERVATION",
    message: str,
    evidence_refs: Optional[list[str]] = None,
) -> IncidentTimelineEntry:
    entry = IncidentTimelineEntry(
        incident_id=incident.id,
        timestamp=timestamp or datetime.now(timezone.utc),
        event_id=event_id,
        source=source,
        kind=kind,
        message=message,
        evidence_refs=evidence_refs or [],
    )
    db.add(entry)
    # Timeline activity reflects on the incident itself (recency, SOC views)
    incident.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(entry)
    return entry


def update_status(db: Session, incident: Incident, status: str, message: str = "") -> Incident:
    incident.status = status
    incident.updated_at = datetime.now(timezone.utc)
    if status in {"CLOSED", "RESOLVED"}:
        incident.closed_at = datetime.now(timezone.utc)
    db.commit()
    if message:
        add_timeline(db, incident, kind="RESPONSE", message=message)
    return incident


def correlate_finding(db: Session, incident: Incident, finding_id: str) -> Incident:
    refs = [r for r in (incident.related_findings or []) if r != finding_id]
    refs.append(finding_id)
    incident.related_findings = refs
    db.commit()
    return incident


def rebuild_timeline_from_events(db: Session, incident: Incident) -> list[IncidentTimelineEntry]:
    """Reconstruct a forensic timeline from the incident's linked events."""
    from ..models import Event

    event_ids = set()
    for entry in incident.timeline:
        if entry.event_id:
            event_ids.add(entry.event_id)
    if not event_ids:
        return incident.timeline
    events = db.query(Event).filter(Event.event_id.in_(event_ids)).order_by(Event.timestamp.asc()).all()
    for ev in events:
        exists = any(t.event_id == ev.event_id for t in incident.timeline)
        if not exists:
            add_timeline(
                db,
                incident,
                timestamp=ev.timestamp,
                event_id=ev.event_id,
                source=ev.source,
                kind="OBSERVATION",
                message=f"{ev.event_type} (severity {ev.severity})",
            )
    db.refresh(incident)
    return sorted(incident.timeline, key=lambda t: t.timestamp)


def incident_dict(incident: Incident) -> dict[str, Any]:
    return {
        "id": incident.id,
        "title": incident.title,
        "severity": incident.severity,
        "status": incident.status,
        "description": incident.description,
        "detection_sources": incident.detection_sources,
        "attack_techniques": incident.attack_techniques,
        "affected_assets": incident.affected_assets,
        "affected_users": incident.affected_users,
        "related_findings": incident.related_findings,
        "root_cause": incident.root_cause,
        "created_at": incident.created_at.isoformat() if incident.created_at else None,
        "updated_at": incident.updated_at.isoformat() if incident.updated_at else None,
    }
