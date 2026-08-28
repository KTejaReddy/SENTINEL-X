"""AI Security Copilot.

Answers org-aware questions by retrieving and reasoning over REAL platform
data (assets, findings, attack paths, incidents, rules, purple coverage).
Answers carry citations; when evidence is missing the answer says so instead
of inventing content.
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from ...models import (
    Asset,
    AttackPath,
    DetectionRule,
    Finding,
    Incident,
    Organization,
    Retest,
)
from ...schemas import AICopilotRequest, AICopilotResponse
from ..attack_paths import get_graph
from ..risk import score_finding
from .providers import PROMPT_VERSIONS, get_provider

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def _citation(kind: str, rid: str, title: str) -> dict:
    return {"type": kind, "id": rid, "title": title}


def _top_findings(db: Session, org_id: str, limit: int = 5) -> list[Finding]:
    rows = (
        db.query(Finding)
        .filter(Finding.org_id == org_id, Finding.status.notin_(["CLOSED", "VERIFIED", "FIXED"]))
        .all()
    )
    rows.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity.upper(), 0), f.cvss or 0), reverse=True)
    return rows[:limit]


def _answer_top_vulnerabilities(db: Session, org_id: str, org: Organization) -> AICopilotResponse:
    findings = _top_findings(db, org_id)
    if not findings:
        return AICopilotResponse(answer="INSUFFICIENT EVIDENCE — no open findings in the asset inventory.", insufficient_evidence=["open findings"])
    lines = []
    citations = []
    for f in findings:
        asset = db.get(Asset, f.asset_id) if f.asset_id else None
        lines.append(f"- {f.id} [{f.severity}] {f.title} on {asset.name if asset else 'unknown asset'} (CVSS {f.cvss or 'n/a'})")
        citations.append(_citation("finding", f.id, f.title))
    answer = f"For {org.name}, the highest-risk open findings are:\n" + "\n".join(lines)
    return AICopilotResponse(answer=answer, citations=citations)


def _answer_external_changes(db: Session, org_id: str) -> AICopilotResponse:
    since = datetime.now(timezone.utc) - timedelta(days=1)
    changed = (
        db.query(Asset)
        .filter(
            Asset.org_id == org_id,
            Asset.exposure == "INTERNET_FACING",
            Asset.updated_at >= since,
        )
        .all()
    )
    if not changed:
        return AICopilotResponse(answer="No internet-facing assets changed in the last 24 hours.", citations=[])
    lines = [f"- {a.name} ({a.asset_type}, updated {a.updated_at.isoformat()})" for a in changed]
    return AICopilotResponse(
        answer="Internet-facing assets that changed today:\n" + "\n".join(lines),
        citations=[_citation("asset", a.id, a.name) for a in changed],
    )


def _answer_paths_to_database(db: Session, org_id: str) -> AICopilotResponse:
    paths = (
        db.query(AttackPath)
        .filter(AttackPath.org_id == org_id, AttackPath.status == "ACTIVE")
        .order_by(AttackPath.risk_score.desc())
        .all()
    )
    if not paths:
        return AICopilotResponse(answer="No active attack paths currently reach a high-value destination.", citations=[])
    lines = []
    citations = []
    for p in paths[:5]:
        labels = [n.label for n in sorted(p.nodes, key=lambda n: n.ordinal)]
        lines.append(f"- {p.id} (risk {p.risk_score}): " + " → ".join(labels))
        citations.append(_citation("attack_path", p.id, p.name))
    return AICopilotResponse(answer="Active attack paths:\n" + "\n".join(lines), citations=citations)


def _answer_would_detect(db: Session, org_id: str) -> AICopilotResponse:
    rules = (
        db.query(DetectionRule)
        .filter(DetectionRule.org_id == org_id, DetectionRule.status == "DEPLOYED")
        .count()
    )
    draft = (
        db.query(DetectionRule)
        .filter(DetectionRule.org_id == org_id, DetectionRule.status == "DRAFT")
        .count()
    )
    paths = (
        db.query(AttackPath)
        .filter(AttackPath.org_id == org_id, AttackPath.status == "ACTIVE")
        .count()
    )
    return AICopilotResponse(
        answer=(
            f"Detection posture: {rules} deployed rules, {draft} draft proposals, {paths} active attack paths. "
            "Use the Purple Team page to see per-stage detection coverage for each scenario."
        ),
        citations=[
            _citation("detection_rule", "deployed", f"{rules} deployed rules"),
            _citation("attack_path", "active", f"{paths} active attack paths"),
        ],
    )


def _answer_incidents_for_finding(db: Session, org_id: str, finding_id: str | None) -> AICopilotResponse:
    if not finding_id:
        return AICopilotResponse(answer="Please specify a finding ID (e.g. 'F-1042').", insufficient_evidence=["finding id"])
    incidents = db.query(Incident).filter(Incident.org_id == org_id).all()
    related = [i for i in incidents if finding_id in (i.related_findings or [])]
    if not related:
        return AICopilotResponse(answer=f"INSUFFICIENT EVIDENCE — no incident is linked to finding {finding_id}.", insufficient_evidence=[f"incident for {finding_id}"])
    lines = [f"- {i.id} [{i.severity}] {i.title} ({i.status})" for i in related]
    return AICopilotResponse(
        answer=f"Incidents related to {finding_id}:\n" + "\n".join(lines),
        citations=[_citation("incident", i.id, i.title) for i in related],
    )


def _answer_biggest_risk_reduction(db: Session, org_id: str) -> AICopilotResponse:
    findings = _top_findings(db, org_id)
    if not findings:
        return AICopilotResponse(answer="No open findings to prioritize.", insufficient_evidence=["open findings"])
    scored = []
    for f in findings:
        asset = db.get(Asset, f.asset_id) if f.asset_id else None
        risk = score_finding(f, asset)
        scored.append((risk["score"], f, risk))
    scored.sort(reverse=True)
    lines = []
    citations = []
    for score, f, risk in scored[:5]:
        lines.append(f"- {f.id} (risk {score}): {f.title} — remediate with: {f.remediation or 'see finding details'}")
        citations.append(_citation("finding", f.id, f.title))
    return AICopilotResponse(
        answer="Remediating these findings gives the largest risk reduction (highest to lowest):\n" + "\n".join(lines),
        citations=citations,
    )


def _answer_deployment_changes(db: Session, org_id: str) -> AICopilotResponse:
    since = datetime.now(timezone.utc) - timedelta(days=2)
    changed = (
        db.query(Finding)
        .filter(Finding.org_id == org_id, Finding.updated_at >= since)
        .order_by(Finding.updated_at.desc())
        .limit(8)
        .all()
    )
    if not changed:
        return AICopilotResponse(answer="No findings changed in the last 48 hours.", citations=[])
    lines = [f"- {f.id} [{f.status}] {f.title} (updated {f.updated_at.isoformat()})" for f in changed]
    return AICopilotResponse(
        answer="Findings that changed after recent activity:\n" + "\n".join(lines),
        citations=[_citation("finding", f.id, f.title) for f in changed],
    )


def _answer_weakest_control(db: Session, org_id: str) -> AICopilotResponse:
    graph = get_graph(db, org_id)
    deployed = (
        db.query(DetectionRule).filter(DetectionRule.org_id == org_id, DetectionRule.status == "DEPLOYED").count()
    )
    draft = (
        db.query(DetectionRule).filter(DetectionRule.org_id == org_id, DetectionRule.status == "DRAFT").count()
    )
    uncovered_assets = sum(
        1 for n in graph["nodes"] if n["finding_count"] > 0 and n["critical_findings"] > 0 and not n["incident"]
    )
    answer = (
        f"Control assessment: {deployed} deployed rules and {draft} draft proposals. "
        f"{uncovered_assets} assets carry critical/high findings with no open incident — "
        "these represent the weakest monitored controls."
    )
    return AICopilotResponse(answer=answer, citations=[_citation("attack_path", "graph", "live attack graph")])


def _answer_generic(db: Session, org_id: str, org: Organization, question: str) -> AICopilotResponse:
    """Fallback: honest answer over available data, never a fabricated one."""
    counts = {
        "assets": db.query(Asset).filter(Asset.org_id == org_id).count(),
        "open findings": db.query(Finding).filter(Finding.org_id == org_id, Finding.status.notin_(["CLOSED", "VERIFIED", "FIXED"])).count(),
        "active attack paths": db.query(AttackPath).filter(AttackPath.org_id == org_id, AttackPath.status == "ACTIVE").count(),
        "open incidents": db.query(Incident).filter(Incident.org_id == org_id, Incident.status.notin_(["CLOSED", "RESOLVED"])).count(),
        "deployed detection rules": db.query(DetectionRule).filter(DetectionRule.org_id == org_id, DetectionRule.status == "DEPLOYED").count(),
    }
    answer = (
        f"I can answer questions about your actual security data. For {org.name} I currently know: "
        + ", ".join(f"{k}: {v}" for k, v in counts.items())
        + ". Ask about most dangerous vulnerabilities, changed external assets, attack paths, incidents, or remediation priorities."
    )
    return AICopilotResponse(answer=answer, citations=[_citation("organization", org.id, org.name)])


def answer_question(db: Session, org_id: str, request: AICopilotRequest, agent_id: str | None = None) -> AICopilotResponse:
    org = db.query(Organization).filter(Organization.id == org_id).first()
    q = request.question.lower()

    handlers = [
        (r"dangerous|vulnerab|critical (finding|vuln)|highest.risk", lambda: _answer_top_vulnerabilities(db, org_id, org)),
        (r"external asset|changed today|exposed.*chang", lambda: _answer_external_changes(db, org_id)),
        (r"path.*(database|db|high.value)|attack path", lambda: _answer_paths_to_database(db, org_id)),
        (r"would.*(detect|soc)|detection (coverage|posture|gap)", lambda: _answer_would_detect(db, org_id)),
        (r"incident.*(related|linked)|related.*incident", lambda: _answer_incidents_for_finding(db, org_id, _extract_finding_id(q))),
        (r"risk reduction|remediation.*(biggest|largest|priority)", lambda: _answer_biggest_risk_reduction(db, org_id)),
        (r"deployment|changed (after|recently)|yesterday", lambda: _answer_deployment_changes(db, org_id)),
        (r"weakest|control.*(weak|gap)|not.*detect", lambda: _answer_weakest_control(db, org_id)),
    ]
    for pattern, handler in handlers:
        if re.search(pattern, q):
            return handler()

    return _answer_generic(db, org_id, org, request.question)


def _extract_finding_id(q: str) -> str | None:
    match = re.search(r"\b(f-\d+|[a-z0-9]{20,32})\b", q)
    return match.group(1).upper() if match else None
