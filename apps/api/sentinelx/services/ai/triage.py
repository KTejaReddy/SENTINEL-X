"""AI Vulnerability Triage.

Receives a structured finding and produces a validated triage. The output is
validated against a strict Pydantic schema. The local provider derives
everything from real platform data — it never asserts evidence that does not
exist.
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy.orm import Session

from ...models import AgentRun, Asset, AttackPath, Finding
from ...schemas import AITriageResponse
from ..risk import score_finding
from .providers import PROMPT_VERSIONS, get_provider

CLASSIFICATION_BY_STATUS = {
    "VALIDATED": "validated",
    "VALIDATING": "validated_candidate",
    "NEW": "candidate",
    "TRIAGED": "candidate",
}


def triage_finding(db: Session, finding: Finding, agent_id: str | None = None) -> AITriageResponse:
    asset = db.get(Asset, finding.asset_id) if finding.asset_id else None

    # Detection coverage for this asset (fraction of deployed rules matching its events)
    from ..events import rule_matches

    from ...models import DetectionRule, Event

    events = (
        db.query(Event)
        .filter(Event.org_id == finding.org_id, Event.asset_id == finding.asset_id)
        .order_by(Event.timestamp.desc())
        .limit(100)
        .all()
    )
    deployed = (
        db.query(DetectionRule)
        .filter(DetectionRule.org_id == finding.org_id, DetectionRule.status == "DEPLOYED")
        .all()
    )
    covered = sum(1 for r in deployed if rule_matches(r, events)[0])
    detection_coverage = covered / len(deployed) if deployed else 0.5

    risk = score_finding(finding, asset, detection_coverage)

    # Does this finding participate in an active attack path?
    in_path = False
    if finding.asset_id:
        from ...models import AttackPathNode

        in_path = (
            db.query(AttackPathNode)
            .join(AttackPath)
            .filter(
                AttackPath.org_id == finding.org_id,
                AttackPath.status == "ACTIVE",
                AttackPathNode.asset_id == finding.asset_id,
            )
            .first()
            is not None
        )

    evidence_required: list[str] = []
    if not finding.validated:
        evidence_required.append("controlled validation result (authorized replay or tool output)")
    if not finding.cve and not finding.cwe:
        evidence_required.append("CVE/CWE classification")
    if finding.endpoint:
        evidence_required.append("reproducible request/response evidence")

    response = AITriageResponse(
        classification=CLASSIFICATION_BY_STATUS.get(finding.status, "candidate"),
        severity=finding.severity.upper(),
        confidence=min(0.99, max(0.5, finding.confidence * (1.0 if finding.validated else 0.85))),
        asset_criticality=(asset.criticality if asset else "MEDIUM") or "MEDIUM",
        business_risk="HIGH" if risk["score"] >= 75 else ("MEDIUM" if risk["score"] >= 50 else "LOW"),
        likely_attack_path=in_path,
        evidence_required=evidence_required,
        recommended_validation=(
            "authorization_boundary_check" if finding.category and "author" in finding.category.lower()
            else "controlled_replay"
        ),
        remediation=finding.remediation or "",
        finding_id=finding.id,
    )

    # Record the AI run for auditability
    run = AgentRun(
        agent_id=agent_id,
        org_id=finding.org_id,
        status="completed",
        input={"finding_id": finding.id, "title": finding.title, "severity": finding.severity, "cvss": finding.cvss},
        output=response.model_dump(),
        model=get_provider().model,
        prompt_version=PROMPT_VERSIONS["triage"],
        started_at=datetime.now(timezone.utc),
        finished_at=datetime.now(timezone.utc),
    )
    db.add(run)
    finding.ai_triage = response.model_dump()
    db.commit()
    return response
