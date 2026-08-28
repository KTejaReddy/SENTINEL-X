"""Purple Team engine.

Measures whether the defensive controls actually detect and respond to
controlled offensive activity:

  RED ACTION → EXPECTED TELEMETRY → ACTUAL TELEMETRY → DETECTION? RESPONSE?

Produces a per-stage coverage matrix and detection proposals for gaps.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from ..models import Asset, DetectionRule, Event, Incident, IncidentTimelineEntry
from .events import rule_matches


def _incident_response_count(db: Session, incident_id: str) -> int:
    if not incident_id:
        return 0
    return (
        db.query(IncidentTimelineEntry)
        .filter(IncidentTimelineEntry.incident_id == incident_id, IncidentTimelineEntry.kind == "RESPONSE")
        .count()
    )


def compute_coverage(
    db: Session,
    org_id: str,
    scenario: dict[str, Any],
    events: list[Event],
    incident_id: str | None = None,
) -> dict[str, Any]:
    """Compute coverage matrix for a scenario's stages."""
    deployed_rules = (
        db.query(DetectionRule)
        .filter(DetectionRule.org_id == org_id, DetectionRule.status == "DEPLOYED")
        .all()
    )
    stages_out: list[dict[str, Any]] = []
    gaps: list[dict[str, Any]] = []
    response_count = _incident_response_count(db, incident_id) if incident_id else 0

    for stage in scenario.get("stages", []):
        stage_name = stage["stage"]
        expected_types = [e[0] for e in stage.get("events", [])]
        stage_events = [e for e in events if e.event_type in expected_types]

        has_telemetry = bool(stage_events)
        detected = False
        matched_rule = None
        for rule in deployed_rules:
            ok, _ = rule_matches(rule, stage_events)
            if ok:
                detected = True
                matched_rule = rule.rule_id
                break
        covered = has_telemetry and detected
        stage_out = {
            "stage": stage_name,
            "technique": stage.get("technique", ""),
            "mitre": stage.get("technique", ""),
            "expected_telemetry": expected_types,
            "observed_telemetry": sorted({e.event_type for e in stage_events}),
            "has_telemetry": has_telemetry,
            "detected": detected,
            "matched_rule": matched_rule,
            "response": response_count > 0 if detected else False,
            "covered": covered,
            "status": "covered" if covered else ("gap" if has_telemetry else "not_observed"),
        }
        stages_out.append(stage_out)
        if has_telemetry and not detected:
            gaps.append(
                {
                    "stage": stage_name,
                    "technique": stage.get("technique", ""),
                    "missing_telemetry": [],
                    "recommended_detection": f"Rule to detect {stage_name} ({expected_types})",
                    "suggested_event_type": expected_types[0] if expected_types else "",
                }
            )

    total = len(stages_out)
    covered = sum(1 for s in stages_out if s["covered"])
    return {
        "coverage": {
            "total_stages": total,
            "covered": covered,
            "gaps": total - covered,
            "coverage_pct": round(covered / total * 100, 1) if total else 0.0,
            "response_executed": response_count > 0,
        },
        "stages": stages_out,
        "gaps": gaps,
    }


def create_gap_recommendations(db: Session, org_id: str, gaps: list[dict[str, Any]], created_by: str | None = None) -> list[DetectionRule]:
    from .events import proposed_rule_from_gap

    rules = []
    for gap in gaps:
        rule = proposed_rule_from_gap(db, org_id, gap, created_by=created_by)
        rules.append(rule)
    return rules


def coverage_summary(db: Session, org_id: str) -> dict[str, Any]:
    """Overall coverage across all purple exercises (latest per scenario)."""
    from ..models import Report

    return {
        "detection_rules_deployed": (
            db.query(DetectionRule).filter(DetectionRule.org_id == org_id, DetectionRule.status == "DEPLOYED").count()
        ),
        "detection_rules_draft": (
            db.query(DetectionRule).filter(DetectionRule.org_id == org_id, DetectionRule.status == "DRAFT").count()
        ),
        "purple_exercises": db.query(Report).filter(Report.org_id == org_id, Report.report_type == "purple").count(),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
