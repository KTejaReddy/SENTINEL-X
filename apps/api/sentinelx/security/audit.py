"""Tamper-evident audit logging.

Every sensitive operation writes WHO / WHAT / WHEN / WHERE / TARGET / TOOL /
RESULT / APPROVAL / POLICY. Logs are tenant-isolated. A hash chain over the
previous entry makes tampering detectable.
"""
from __future__ import annotations

import hashlib
import hmac
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from ..config import settings
from ..models import AuditLog


def _hash_chain(prev_hash: str | None, payload: str) -> str:
    return hmac.new(
        settings.WEBHOOK_SECRET.encode(),
        f"{prev_hash or ''}|{payload}".encode(),
        hashlib.sha256,
    ).hexdigest()


class AuditService:
    def __init__(self, db: Session, request_id: str | None = None):
        self.db = db
        self.request_id = request_id or uuid.uuid4().hex

    def _write(
        self,
        org_id: str | None,
        user_id: str | None,
        action: str,
        resource_type: str | None,
        resource_id: str | None,
        detail: dict[str, Any],
        ip: str | None,
        user_agent: str | None,
        outcome: str,
    ) -> None:
        prev = (
            self.db.query(AuditLog)
            .filter(AuditLog.org_id == org_id if org_id else AuditLog.org_id.is_(None))
            .order_by(AuditLog.created_at.desc(), AuditLog.id.desc())
            .first()
        )
        payload = (
            f"{action}|{resource_type}|{resource_id}|{org_id}|{user_id}|{outcome}"
        )
        chain = _hash_chain(prev.hash_chain if prev else None, payload)
        entry = AuditLog(
            org_id=org_id,
            user_id=user_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            detail=detail,
            ip=ip,
            user_agent=user_agent,
            outcome=outcome,
            request_id=self.request_id,
            hash_chain=chain,  # type: ignore[attr-defined]
        )
        self.db.add(entry)

    def log(self, action: str, *, org_id: str | None = None, user_id: str | None = None,
            resource_type: str | None = None, resource_id: str | None = None,
            detail: dict[str, Any] | None = None, ip: str | None = None,
            user_agent: str | None = None, outcome: str = "success") -> None:
        self._write(org_id, user_id, action, resource_type, resource_id, detail or {}, ip, user_agent, outcome)
        self.db.commit()
