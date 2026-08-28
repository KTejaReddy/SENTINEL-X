"""Command Center data aggregation — computed from live platform state."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy.orm import Session

from ..models import Asset, AttackPath, DetectionRule, Event, Finding, Incident, Retest


def _risk_level(total_risk: float) -> str:
    if total_risk >= 75:
        return "CRITICAL"
    if total_risk >= 50:
        return "HIGH"
    if total_risk >= 25:
        return "ELEVATED"
    return "LOW"


def dashboard(db: Session, org_id: str) -> dict[str, Any]:
    now = datetime.now(timezone.utc)

    open_findings = (
        db.query(Finding)
        .filter(Finding.org_id == org_id, Finding.status.notin_(["CLOSED", "VERIFIED", "FIXED"]))
        .all()
    )
    critical = sum(1 for f in open_findings if f.severity == "CRITICAL")
    high = sum(1 for f in open_findings if f.severity == "HIGH")
    validated = sum(1 for f in open_findings if f.validated)

    exposed = (
        db.query(Asset)
        .filter(Asset.org_id == org_id, Asset.exposure == "INTERNET_FACING")
        .count()
    )
    paths = (
        db.query(AttackPath)
        .filter(AttackPath.org_id == org_id, AttackPath.status == "ACTIVE")
        .all()
    )
    total_path_risk = sum(p.risk_score for p in paths)

    open_incidents = (
        db.query(Incident)
        .filter(Incident.org_id == org_id, Incident.status.in_(["OPEN", "INVESTIGATING", "CONTAINED", "ERADICATION", "RECOVERY"]))
        .all()
    )
    deployed_rules = db.query(DetectionRule).filter(DetectionRule.org_id == org_id, DetectionRule.status == "DEPLOYED").count()
    draft_rules = db.query(DetectionRule).filter(DetectionRule.org_id == org_id, DetectionRule.status == "DRAFT").count()
    detection_coverage = deployed_rules / (deployed_rules + draft_rules) if (deployed_rules + draft_rules) else 0.0

    events = db.query(Event).filter(Event.org_id == org_id, Event.timestamp >= now - timedelta(hours=24)).all()
    if events:
        sorted_events = sorted(events, key=lambda e: e.timestamp)
        # First high/critical event after an earlier low event in the window ≈ detection latency
        first_high = next((e for e in sorted_events if e.severity in {"high", "critical"}), None)
        mttd_min = None
        if first_high:
            mttd_min = round((first_high.timestamp - sorted_events[0].timestamp).total_seconds() / 60, 1)
        else:
            mttd_min = 0.0
    else:
        mttd_min = None

    incidents_recent = db.query(Incident).filter(Incident.org_id == org_id).all()
    mttr_min = None
    resolved = [i for i in incidents_recent if i.closed_at and i.created_at]
    if resolved:
        deltas = [(i.closed_at - i.created_at).total_seconds() / 60 for i in resolved]
        mttr_min = round(sum(deltas) / len(deltas), 1)

    retests = db.query(Retest).filter(Retest.org_id == org_id).all()
    regressions = sum(1 for r in retests if r.status == "FAILED")

    total_risk = min(
        100.0,
        critical * 22 + high * 8 + validated * 4 + len(paths) * 5
        + (10 if exposed > 0 else 0)
        + (10 if not detection_coverage else 0)
        + (5 if regressions else 0),
    )

    posture = {
        "overall_risk": round(total_risk, 1),
        "risk_level": _risk_level(total_risk),
        "critical_findings": critical,
        "high_findings": high,
        "validated_vulnerabilities": validated,
        "exposed_assets": exposed,
        "active_attack_paths": len(paths),
        "open_incidents": len(open_incidents),
        "detection_coverage": round(detection_coverage * 100, 1),
        "mttd_minutes": mttd_min,
        "mttr_minutes": mttr_min,
        "security_regressions": regressions,
    }

    recent_events = (
        db.query(Event).filter(Event.org_id == org_id).order_by(Event.timestamp.desc()).limit(15).all()
    )
    recent_incidents = (
        db.query(Incident).filter(Incident.org_id == org_id).order_by(Incident.created_at.desc()).limit(8).all()
    )
    recent_findings = (
        db.query(Finding).filter(Finding.org_id == org_id).order_by(Finding.created_at.desc()).limit(8).all()
    )
    new_assets = (
        db.query(Asset).filter(Asset.org_id == org_id).order_by(Asset.created_at.desc()).limit(8).all()
    )
    detection_gaps = draft_rules

    return {
        "posture": posture,
        "live_events": [
            {"id": e.id, "timestamp": e.timestamp.isoformat(), "source": e.source, "event_type": e.event_type, "severity": e.severity, "demo": e.demo}
            for e in recent_events
        ],
        "live_incidents": [
            {"id": i.id, "title": i.title, "severity": i.severity, "status": i.status, "created_at": i.created_at.isoformat()}
            for i in recent_incidents
        ],
        "top_attack_paths": [
            {"id": p.id, "name": p.name, "risk_score": p.risk_score, "status": p.status}
            for p in sorted(paths, key=lambda p: p.risk_score, reverse=True)[:5]
        ],
        "new_assets": [
            {"id": a.id, "name": a.name, "asset_type": a.asset_type, "exposure": a.exposure, "criticality": a.criticality}
            for a in new_assets
        ],
        "critical_findings": [
            {"id": f.id, "title": f.title, "severity": f.severity, "cvss": f.cvss, "status": f.status, "validated": f.validated}
            for f in sorted(open_findings, key=lambda f: f.cvss or 0, reverse=True)[:8]
        ],
        "detection_gaps": {
            "deployed_rules": deployed_rules,
            "draft_rules": draft_rules,
            "suggestions": [
                {"rule_id": r.rule_id, "name": r.name, "status": r.status}
                for r in db.query(DetectionRule).filter(DetectionRule.org_id == org_id, DetectionRule.status == "DRAFT").limit(5).all()
            ],
        },
        "recent_remediation": [
            {"id": r.id, "finding_id": r.finding_id, "status": r.status, "created_at": r.created_at.isoformat()}
            for r in db.query(Retest).filter(Retest.org_id == org_id).order_by(Retest.created_at.desc()).limit(5).all()
        ],
        "generated_at": now.isoformat(),
    }
