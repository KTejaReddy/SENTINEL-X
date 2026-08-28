"""Evidence Vault.

Evidence is content-addressed (SHA-256), immutable by default, tenant-isolated
and optionally mirrored to object storage. Never fabricate evidence: entries
are only created from real tool output, events or user uploads.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from sqlalchemy.orm import Session

from ..config import settings
from ..models import Evidence


def _content_hash(data: dict[str, Any]) -> str:
    canonical = json.dumps(data, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _mirror_to_storage(content_hash: str, data: dict[str, Any]) -> Optional[str]:
    """Persist large evidence payloads to object storage path. Returns storage ref."""
    try:
        root = Path(settings.OBJECT_STORAGE_PATH)
        root.mkdir(parents=True, exist_ok=True)
        path = root / f"{content_hash}.json"
        if not path.exists():
            path.write_text(json.dumps(data, default=str, indent=2), encoding="utf-8")
        return str(path)
    except OSError:
        return None


def store_evidence(
    db: Session,
    *,
    org_id: str,
    finding_id: Optional[str] = None,
    incident_id: Optional[str] = None,
    engagement_id: Optional[str] = None,
    kind: str = "TOOL_OUTPUT",
    data: dict[str, Any],
    tool: Optional[str] = None,
    demo: bool = False,
    captured_at: Optional[datetime] = None,
    created_by: Optional[str] = None,
) -> Evidence:
    content_hash = _content_hash(data)
    existing = db.query(Evidence).filter(Evidence.org_id == org_id, Evidence.content_hash == content_hash).first()
    if existing:
        return existing
    storage_ref = _mirror_to_storage(content_hash, data)
    ev = Evidence(
        org_id=org_id,
        finding_id=finding_id,
        incident_id=incident_id,
        engagement_id=engagement_id,
        kind=kind,
        content_hash=content_hash,
        storage_ref=storage_ref,
        data=data,
        tool=tool,
        demo=demo,
        captured_at=captured_at or datetime.now(timezone.utc),
        created_by=created_by,
    )
    db.add(ev)
    db.commit()
    db.refresh(ev)
    return ev


def link_evidence_to_finding(db: Session, finding_id: str, evidence_id: str) -> None:
    from ..models import Finding

    finding = db.get(Finding, finding_id)
    if finding is None:
        return
    refs = [r for r in (finding.evidence_refs or []) if r != evidence_id]
    refs.append(evidence_id)
    finding.evidence_refs = refs
    db.commit()


def evidence_for_finding(db: Session, finding_id: str) -> list[Evidence]:
    return db.query(Evidence).filter(Evidence.finding_id == finding_id).order_by(Evidence.created_at).all()
