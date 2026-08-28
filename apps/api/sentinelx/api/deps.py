"""Shared FastAPI dependencies.

Tenant context is always derived server-side from the authenticated identity —
a tenant id supplied by the frontend is never trusted.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Optional

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import Organization, User
from ..security.auth import get_current_user
from ..security.audit import AuditService


@dataclass
class RequestContext:
    request_id: str
    ip: str
    user_agent: str
    user: User
    org: Optional[Organization]
    audit: AuditService


def get_request_context(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> RequestContext:
    request_id = request.headers.get("X-Request-ID") or uuid.uuid4().hex
    org = db.get(Organization, user.org_id) if user.org_id else None
    audit = AuditService(db, request_id=request_id)
    return RequestContext(
        request_id=request_id,
        ip=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent", "")[:255],
        user=user,
        org=org,
        audit=audit,
    )


def require_org(ctx: RequestContext = Depends(get_request_context)) -> RequestContext:
    """Dependency ensuring the user belongs to an organization (tenant context)."""
    if ctx.org is None:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="No organization context")
    return ctx


def require_permission(permission: str):
    """Dependency: current user's role must grant the permission."""

    def dep(user: User = Depends(get_current_user)) -> User:
        from ..security.rbac import has_permission

        if not has_permission(user.role, permission):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=f"Missing permission: {permission}")
        return user

    return dep


def check_permission(user: User, permission: str) -> None:
    """Raise 403 unless the user's role grants the permission (for sync handlers)."""
    from ..security.rbac import has_permission

    if not has_permission(user.role, permission):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=f"Missing permission: {permission}")


def ctx_audit(ctx: RequestContext, action: str, *, resource_type: str | None = None,
              resource_id: str | None = None, detail: dict | None = None, outcome: str = "success") -> None:
    ctx.audit.log(
        action,
        org_id=ctx.org.id if ctx.org else None,
        user_id=ctx.user.id,
        resource_type=resource_type,
        resource_id=resource_id,
        detail=detail,
        ip=ctx.ip,
        user_agent=ctx.user_agent,
        outcome=outcome,
    )


def paginate(query, page: int = 1, size: int = 50):
    page = max(1, page)
    size = min(200, max(1, size))
    return query.offset((page - 1) * size).limit(size).all()
