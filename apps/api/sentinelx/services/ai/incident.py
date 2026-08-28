"""AI SOC Analyst.

Receives an incident with its timeline/events/findings and produces a
structured analysis that explicitly separates FACT, INFERENCE, HYPOTHESIS and
RECOMMENDATION. Facts come only from stored data.
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy.orm import Session

from ...models import AgentRun, Event, Finding, Incident, IncidentTimelineEntry
from ...schemas import AIIncidentAnalysis
from .providers import PROMPT_VERSIONS, get_provider

STAGE_BY_EVENT = {
    "network:port_scan": "Recon",
    "authentication:login_attempt": "Initial Access",
    "authentication:api_token_use": "Initial Access",
    "authentication:privilege_boundary": "Privilege Escalation",
    "web:api_request": "Execution",
    "api:function_level_authorization": "Privilege Escalation",
    "network:internal_connection": "Lateral Movement",
    "data:sensitive_access": "Collection",
    "data:credential_use": "Credential Access",
    "repo:secret_scan_hit": "Credential Access",
    "cloud:anonymous_read": "Initial Access",
    "cloud:public_bucket_probe": "Recon",
    "repo:clone": "Recon",
}


def analyze_incident(db: Session, incident: Incident, agent_id: str | None = None) -> AIIncidentAnalysis:
    timeline = sorted(incident.timeline, key=lambda t: t.timestamp)
    event_ids = [t.event_id for t in timeline if t.event_id]
    events = db.query(Event).filter(Event.event_id.in_(event_ids)).all() if event_ids else []
    findings = (
        db.query(Finding).filter(Finding.id.in_(incident.related_findings or [])).all()
        if incident.related_findings
        else []
    )

    facts: list[str] = [
        f"Incident '{incident.title}' opened at {incident.created_at.isoformat()} with severity {incident.severity}",
        f"{len(timeline)} timeline entries recorded",
    ]
    for ev in sorted(events, key=lambda e: e.timestamp)[:10]:
        facts.append(f"{ev.timestamp.isoformat()} {ev.source}: {ev.event_type} (severity {ev.severity})")
    for f in findings[:10]:
        facts.append(f"Finding {f.id} ({f.severity}): {f.title}")

    stages = [STAGE_BY_EVENT.get(e.event_type, "Other") for e in events]
    attack_stage = stages[-1] if stages else "unknown"

    inferences: list[str] = []
    if events:
        earliest = min(e.timestamp for e in events)
        inferences.append(f"Activity began around {earliest.isoformat()} based on first observed event")
    if findings:
        inferences.append(f"{len(findings)} related finding(s) suggest a vulnerability-driven root cause")

    hypotheses: list[str] = []
    if any(e.event_type == "data:sensitive_access" for e in events):
        hypotheses.append("Sensitive data may have been accessed by an unauthorized principal")
    if any(e.event_type == "network:internal_connection" for e in events):
        hypotheses.append("Lateral movement may have occurred; verify the internal connection target")

    recommendations: list[str] = [
        "Correlate all events sharing the affected asset with identity context",
        "Check whether the related findings participate in an active attack path",
        "Run a response playbook for containment and evidence collection",
    ]
    if not incident.ai_analysis.get("run_once"):
        recommendations.append("Re-run AI analysis after the investigation progresses")

    confidence = round(0.5 + 0.35 * min(1.0, len(events) / 6) + 0.15 * min(1.0, len(findings) / 2), 2)

    analysis = AIIncidentAnalysis(
        summary=f"{incident.title} — {attack_stage} stage reached based on {len(events)} observed events.",
        evidence=[{"event_id": e.event_id, "type": e.event_type, "ts": e.timestamp.isoformat(), "severity": e.severity} for e in events[:10]],
        affected_assets=incident.affected_assets or [],
        affected_identities=incident.affected_users or [],
        timeline=[{"ts": t.timestamp.isoformat(), "kind": t.kind, "message": t.message} for t in timeline],
        attack_stage=attack_stage,
        possible_root_cause=findings[0].title if findings else "Not yet determined",
        confidence=confidence,
        facts=facts,
        inferences=inferences,
        hypotheses=hypotheses,
        recommendations=recommendations,
    )

    run = AgentRun(
        agent_id=agent_id,
        org_id=incident.org_id,
        status="completed",
        input={"incident_id": incident.id, "title": incident.title, "status": incident.status},
        output=analysis.model_dump(),
        model=get_provider().model,
        prompt_version=PROMPT_VERSIONS["incident"],
        started_at=datetime.now(timezone.utc),
        finished_at=datetime.now(timezone.utc),
    )
    db.add(run)
    incident.ai_analysis = {**incident.ai_analysis, **analysis.model_dump(), "run_once": True}
    db.commit()
    return analysis
