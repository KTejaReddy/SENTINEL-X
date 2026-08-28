"""Finding engine: ingestion, correlation and deduplication.

Multiple scanners may report the same underlying issue. A deterministic
dedup_key (org + asset + endpoint + vulnerability class) collapses duplicates
into a single finding while preserving a source trail.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from ..models import Asset, Finding

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def dedup_key(org_id: str, asset_id: str | None, endpoint: str | None, cve: str | None, cwe: str | None, category: str | None) -> str:
    parts = [
        org_id,
        asset_id or "",
        (endpoint or "").strip().rstrip("/").lower(),
        cve or "",
        cwe or "",
        (category or "").lower(),
    ]
    return hashlib.sha1("|".join(parts).encode()).hexdigest()


def ingest_normalized(
    db: Session,
    org_id: str,
    engagement_id: str,
    normalized_findings: list[Any],
    tool: str,
    demo: bool = False,
) -> tuple[int, int, list[tuple[str, dict]]]:
    """Persist normalized findings with deduplication.

    Returns (created, updated, linked_evidence) where linked_evidence is a list
    of (finding_id, evidence_data) to attach to the evidence vault.
    """
    created = 0
    updated = 0
    linked: list[tuple[str, dict]] = []

    for nf in normalized_findings:
        asset = None
        if nf.asset_ip:
            asset = db.query(Asset).filter(Asset.org_id == org_id, Asset.ip_address == nf.asset_ip).first()
        elif nf.asset_name:
            asset = db.query(Asset).filter(Asset.org_id == org_id, Asset.name == nf.asset_name).first()
        asset_id = asset.id if asset else None

        key = dedup_key(org_id, asset_id, nf.endpoint, nf.cve, nf.cwe, nf.category)
        existing = (
            db.query(Finding)
            .filter(Finding.org_id == org_id, Finding.dedup_key == key, Finding.status != "CLOSED")
            .first()
        )
        if existing:
            existing.updated_at = datetime.now(timezone.utc)
            existing.confidence = max(existing.confidence, nf.confidence)
            existing.metadata_json = {
                **(existing.metadata_json or {}),
                "last_reported_by": tool,
                "occurrences": (existing.metadata_json or {}).get("occurrences", 1) + 1,
            }
            if nf.evidence:
                linked.append((existing.id, nf.evidence))
            updated += 1
            continue

        finding = Finding(
            org_id=org_id,
            engagement_id=engagement_id,
            asset_id=asset_id,
            title=nf.title,
            description=nf.description,
            severity=nf.severity if nf.severity in SEVERITY_ORDER else "MEDIUM",
            cvss=nf.cvss,
            cvss_vector=nf.cvss_vector,
            cve=nf.cve,
            cwe=nf.cwe,
            category=nf.category,
            source=tool,
            endpoint=nf.endpoint,
            confidence=nf.confidence,
            remediation=nf.remediation,
            dedup_key=key,
            status="NEW",
            demo=demo,
            metadata_json={"first_reported_by": tool, "occurrences": 1, **(nf.metadata or {})},
        )
        db.add(finding)
        db.flush()
        if nf.evidence:
            linked.append((finding.id, nf.evidence))
        created += 1
    db.commit()
    return created, updated, linked


def set_status(db: Session, finding: Finding, status: str, reason: str = "") -> Finding:
    finding.status = status
    finding.metadata_json = {**(finding.metadata_json or {}), "status_change_note": reason}
    finding.updated_at = datetime.now(timezone.utc)
    db.commit()
    return finding


def validate_finding(db: Session, finding: Finding, evidence_data: dict[str, Any] | None = None, tool: str = "controlled-validation") -> Finding:
    """Mark a finding as validated only when evidence exists."""
    from .evidence import store_evidence

    if evidence_data:
        store_evidence(
            db,
            org_id=finding.org_id,
            finding_id=finding.id,
            engagement_id=finding.engagement_id,
            kind="TEST_RESULT",
            data=evidence_data,
            tool=tool,
            demo=finding.demo,
            created_by="system",
        )
    finding.validated = True
    finding.status = "VALIDATED"
    finding.updated_at = datetime.now(timezone.utc)
    db.commit()
    return finding


def top_findings(db: Session, org_id: str, limit: int = 10) -> list[Finding]:
    return (
        db.query(Finding)
        .filter(Finding.org_id == org_id, Finding.status.notin_(["CLOSED", "VERIFIED", "FIXED"]))
        .order_by(Finding.severity.asc(), Finding.cvss.desc())
        .limit(limit)
        .all()
    )
