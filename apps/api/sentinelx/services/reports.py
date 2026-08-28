"""Reporting engine.

Structured templates rendered from real platform data. Never fabricate: every
section is populated from stored entities.
"""
from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from ..config import settings
from ..models import (
    Asset,
    AttackPath,
    Engagement,
    Event,
    Finding,
    Incident,
    Organization,
    Retest,
)


def _org_data(db: Session, org_id: str) -> dict[str, Any]:
    org = db.query(Organization).filter(Organization.id == org_id).first()
    return {
        "org_name": org.name if org else "Unknown",
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


def _findings_data(db: Session, org_id: str) -> list[dict[str, Any]]:
    findings = (
        db.query(Finding)
        .filter(Finding.org_id == org_id)
        .order_by(Finding.severity.desc(), Finding.cvss.desc())
        .all()
    )
    out = []
    for f in findings:
        asset = db.get(Asset, f.asset_id) if f.asset_id else None
        out.append(
            {
                "id": f.id,
                "title": f.title,
                "severity": f.severity,
                "cvss": f.cvss,
                "cve": f.cve,
                "cwe": f.cwe,
                "category": f.category,
                "status": f.status,
                "validated": f.validated,
                "asset": asset.name if asset else None,
                "endpoint": f.endpoint,
                "remediation": f.remediation,
                "source": f.source,
            }
        )
    return out


def _path_data(db: Session, org_id: str) -> list[dict[str, Any]]:
    paths = db.query(AttackPath).filter(AttackPath.org_id == org_id, AttackPath.status == "ACTIVE").all()
    out = []
    for p in paths:
        out.append(
            {
                "id": p.id,
                "name": p.name,
                "risk_score": p.risk_score,
                "path": [{"label": n.label, "role": n.role, "evidence": n.evidence_refs} for n in sorted(p.nodes, key=lambda n: n.ordinal)],
            }
        )
    return out


def _incident_data(db: Session, org_id: str) -> list[dict[str, Any]]:
    incidents = db.query(Incident).filter(Incident.org_id == org_id).order_by(Incident.created_at.desc()).all()
    return [
        {
            "id": i.id,
            "title": i.title,
            "severity": i.severity,
            "status": i.status,
            "techniques": i.attack_techniques,
            "created_at": i.created_at.isoformat() if i.created_at else None,
        }
        for i in incidents
    ]


def _retest_data(db: Session, org_id: str) -> list[dict[str, Any]]:
    return [
        {
            "id": r.id,
            "finding_id": r.finding_id,
            "status": r.status,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in db.query(Retest).filter(Retest.org_id == org_id).all()
    ]


def _event_data(db: Session, org_id: str) -> list[dict[str, Any]]:
    events = db.query(Event).filter(Event.org_id == org_id).order_by(Event.timestamp.desc()).limit(200).all()
    return [
        {"ts": e.timestamp.isoformat(), "source": e.source, "type": e.event_type, "severity": e.severity, "demo": e.demo}
        for e in events
    ]


def render_markdown(report_type: str, data: dict[str, Any]) -> str:
    org = data["org_name"]
    lines = [f"# {report_type.replace('_', ' ').title()} Report — {org}", ""]
    lines.append(f"Generated: {data['generated_at']}  ")
    lines.append(f"Environment: {data.get('environment', 'development')}  ")
    lines.append("")

    findings = data.get("findings", [])
    paths = data.get("paths", [])
    incidents = data.get("incidents", [])
    retests = data.get("retests", [])

    if report_type in {"executive", "pentest", "bug_bounty", "remediation", "purple"}:
        lines.append("## Executive Summary")
        critical = sum(1 for f in findings if f["severity"] == "CRITICAL")
        high = sum(1 for f in findings if f["severity"] == "HIGH")
        lines.append(
            f"This assessment of {org} identified **{critical} critical** and **{high} high** "
            f"severity findings across {len(data.get('assets', []))} assets, with "
            f"{len(paths)} active attack path(s) and {len(incidents)} incident(s)."
        )
        lines.append("")

    if report_type in {"executive", "pentest", "bug_bounty", "remediation"}:
        lines.append("## Scope")
        lines.append(f"- Assets assessed: {len(data.get('assets', []))}")
        if data.get("engagement"):
            eng = data["engagement"]
            lines.append(f"- Engagement: {eng.get('name', 'n/a')} ({eng.get('status', 'n/a')})")
            for rule in eng.get("scope_rules", []):
                lines.append(f"  - {rule.get('kind')} {rule.get('match_type')}: {rule.get('value')}")
        lines.append("")

        lines.append("## Findings")
        if findings:
            lines.append("| ID | Severity | Title | Asset | Status |")
            lines.append("|----|----------|-------|-------|--------|")
            for f in findings:
                lines.append(f"| {f['id']} | {f['severity']} | {f['title']} | {f.get('asset') or '—'} | {f['status']} |")
            lines.append("")
            lines.append("### Finding Details")
            for f in findings:
                lines.append(f"#### {f['id']} — {f['title']}")
                lines.append(f"- Severity: **{f['severity']}**  CVSS: {f.get('cvss') or 'n/a'}  ")
                lines.append(f"- CVE: {f.get('cve') or '—'}  CWE: {f.get('cwe') or '—'}  Category: {f.get('category') or '—'}")
                lines.append(f"- Status: {f['status']}  Validated: {'yes' if f.get('validated') else 'no'}")
                if f.get("description"):
                    lines.append(f"- Description: {f['description']}")
                if f.get("remediation"):
                    lines.append(f"- Remediation: {f['remediation']}")
                lines.append("")
        else:
            lines.append("No findings recorded.")
            lines.append("")

    if report_type in {"pentest", "executive", "purple"}:
        lines.append("## Attack Paths")
        if paths:
            for p in paths:
                route = " → ".join(n["label"] for n in p["path"])
                lines.append(f"- **{p['id']}** (risk {p['risk_score']}): {route}")
        else:
            lines.append("No active attack paths.")
        lines.append("")

    if report_type in {"soc_incident", "purple", "executive"}:
        lines.append("## Incidents & Detection")
        if incidents:
            for i in incidents:
                lines.append(f"- **{i['id']}** [{i['severity']}] {i['title']} ({i['status']}) — techniques: {', '.join(i['techniques']) or '—'}")
        else:
            lines.append("No incidents recorded.")
        lines.append("")
        lines.append(f"Security events ingested: {len(data.get('events', []))} (latest 200 shown)")

    if report_type in {"remediation", "pentest", "executive", "bug_bounty"}:
        lines.append("## Remediation & Retest")
        if retests:
            passed = sum(1 for r in retests if r["status"] == "PASSED")
            failed = sum(1 for r in retests if r["status"] == "FAILED")
            lines.append(f"Retests executed: {len(retests)} — passed: {passed}, failed/regressed: {failed}")
            for r in retests:
                lines.append(f"- {r['finding_id']}: **{r['status']}**")
        else:
            lines.append("No retests executed yet.")
        lines.append("")

    if report_type == "purple":
        lines.append("## Purple Team Coverage")
        coverage = data.get("purple_coverage", {})
        for stage in coverage.get("stages", []):
            mark = "✓" if stage.get("covered") else "✗"
            lines.append(f"- {stage['stage']}: {mark} (telemetry: {'yes' if stage.get('has_telemetry') else 'no'}, detected: {'yes' if stage.get('detected') else 'no'})")
        lines.append("")
        for gap in coverage.get("gaps", []):
            lines.append(f"- **Gap**: {gap.get('stage')} — recommended detection: {gap.get('recommended_detection')}")

    lines.append("---")
    lines.append("*Generated by SENTINEL X. Reports reflect stored platform data only.*")
    return "\n".join(lines)


def generate_report(
    db: Session,
    org_id: str,
    report_type: str,
    engagement_id: str | None = None,
    created_by: str | None = None,
    title: str | None = None,
) -> dict[str, Any]:
    from ..models import Report

    org = _org_data(db, org_id)
    assets = db.query(Asset).filter(Asset.org_id == org_id).all()
    engagement = db.get(Engagement, engagement_id) if engagement_id else None

    data: dict[str, Any] = {
        **org,
        "environment": settings.ENVIRONMENT,
        "assets": [{"id": a.id, "name": a.name, "type": a.asset_type, "exposure": a.exposure, "criticality": a.criticality} for a in assets],
        "findings": _findings_data(db, org_id),
        "paths": _path_data(db, org_id),
        "incidents": _incident_data(db, org_id),
        "retests": _retest_data(db, org_id),
        "events": _event_data(db, org_id),
        "engagement": (
            {
                "name": engagement.name,
                "status": engagement.status,
                "scope_rules": [{"kind": r.kind, "match_type": r.match_type, "value": r.value} for r in engagement.scope_rules],
            }
            if engagement
            else None
        ),
    }
    if report_type == "purple":
        from .purple import coverage_summary

        data["purple_coverage"] = coverage_summary(db, org_id)

    markdown = render_markdown(report_type, data)
    report_title = title or f"{report_type.replace('_', ' ').title()} Report — {org['org_name']}"
    report = Report(
        org_id=org_id,
        report_type=report_type,
        title=report_title,
        status="generated",
        format="markdown",
        content={"markdown": markdown, "data": data},
        generated_at=datetime.now(timezone.utc),
        created_by=created_by,
        engagement_id=engagement_id,
    )
    db.add(report)
    db.commit()
    db.refresh(report)
    return {"id": report.id, "title": report.title, "markdown": markdown, "data": data}


def export_report(report: Any, fmt: str) -> tuple[str, str, str]:
    """Return (content, media_type, filename) for the requested format."""
    data = report.content.get("data", {})
    markdown = report.content.get("markdown", "")
    base = report.title.replace(" ", "_").lower()
    if fmt == "markdown":
        return markdown, "text/markdown", f"{base}.md"
    if fmt == "html":
        import html as html_mod

        body = "".join(
            f"<h2>{html_mod.escape(line[2:])}</h2>" if line.startswith("## ")
            else f"<h3>{html_mod.escape(line[3:])}</h3>" if line.startswith("### ")
            else f"<h4>{html_mod.escape(line[4:])}</h4>" if line.startswith("#### ")
            else (f"<li>{html_mod.escape(line[2:])}</li>" if line.startswith("- ") else f"<p>{html_mod.escape(line)}</p>")
            for line in markdown.splitlines()
        )
        html = f"<!doctype html><html><head><meta charset='utf-8'><title>{html_mod.escape(report.title)}</title>"
        html += "<style>body{font-family:system-ui;max-width:900px;margin:40px auto;color:#111}h1{border-bottom:2px solid #111}</style></head><body>"
        html += f"<h1>{html_mod.escape(report.title)}</h1>{body}</body></html>"
        return html, "text/html", f"{base}.html"
    if fmt == "json":
        return json.dumps(data, indent=2, default=str), "application/json", f"{base}.json"
    if fmt == "csv":
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["id", "title", "severity", "cvss", "cve", "cwe", "status", "validated", "asset", "endpoint"])
        for f in data.get("findings", []):
            writer.writerow([f.get("id"), f.get("title"), f.get("severity"), f.get("cvss"), f.get("cve"), f.get("cwe"), f.get("status"), f.get("validated"), f.get("asset"), f.get("endpoint")])
        return buf.getvalue(), "text/csv", f"{base}.csv"
    raise ValueError(f"Unsupported format: {fmt}")
