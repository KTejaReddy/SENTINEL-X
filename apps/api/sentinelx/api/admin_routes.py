"""/audit, /notifications, /policies, /agents, /search, /system routes."""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func
from sqlalchemy.orm import Session

from ..config import settings
from ..db import get_db
from ..models import (
    Agent,
    AgentRun,
    Asset,
    AuditLog,
    Engagement,
    Finding,
    Incident,
    Notification,
    Policy,
)
from ..schemas import OrganizationOut
from .deps import (
    RequestContext,
    check_permission,
    ctx_audit,
    get_request_context,
    paginate,
    require_org,
)

router = APIRouter(tags=["admin"])


# ---------- Audit ----------

@router.get("/audit")
def list_audit(
    ctx: RequestContext = Depends(require_org),
    db: Session = Depends(get_db),
    action: str | None = None,
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=200),
):
    check_permission(ctx.user, "audit:read")
    q = db.query(AuditLog).filter(AuditLog.org_id == ctx.org.id)
    if action:
        q = q.filter(AuditLog.action == action)
    entries = paginate(q.order_by(AuditLog.created_at.desc()), page, size)
    return [
        {
            "id": e.id,
            "created_at": e.created_at.isoformat(),
            "user_id": e.user_id,
            "action": e.action,
            "resource_type": e.resource_type,
            "resource_id": e.resource_id,
            "detail": e.detail,
            "outcome": e.outcome,
            "ip": e.ip,
            "request_id": e.request_id,
        }
        for e in entries
    ]


# ---------- Notifications ----------

@router.get("/notifications")
def list_notifications(ctx: RequestContext = Depends(require_org), db: Session = Depends(get_db)):
    check_permission(ctx.user, "notifications:read")
    q = db.query(Notification).filter(Notification.org_id == ctx.org.id)
    if ctx.user.role not in {"SUPER_ADMIN", "ORG_ADMIN"}:
        q = q.filter((Notification.user_id == ctx.user.id) | (Notification.user_id.is_(None)))
    items = q.order_by(Notification.created_at.desc()).limit(100).all()
    return [
        {"id": n.id, "kind": n.kind, "title": n.title, "body": n.body, "link": n.link, "read": n.read, "created_at": n.created_at.isoformat()}
        for n in items
    ]


@router.post("/notifications/{notification_id}/read")
def mark_read(notification_id: str, ctx: RequestContext = Depends(require_org), db: Session = Depends(get_db)):
    check_permission(ctx.user, "notifications:read")
    n = db.query(Notification).filter(Notification.id == notification_id, Notification.org_id == ctx.org.id).first()
    if n is None:
        raise HTTPException(status_code=404, detail="Notification not found")
    n.read = True
    db.commit()
    return {"ok": True}


# ---------- Policies ----------

@router.get("/policies")
def list_policies(ctx: RequestContext = Depends(require_org), db: Session = Depends(get_db)):
    check_permission(ctx.user, "policy:manage")
    return db.query(Policy).filter((Policy.org_id == ctx.org.id) | (Policy.org_id.is_(None))).all()


# ---------- Agents ----------

@router.get("/agents")
def list_agents(ctx: RequestContext = Depends(require_org), db: Session = Depends(get_db)):
    check_permission(ctx.user, "system:read")
    agents = db.query(Agent).filter((Agent.org_id == ctx.org.id) | (Agent.org_id.is_(None))).all()
    return [
        {
            "id": a.id,
            "name": a.name,
            "role": a.role,
            "permissions": a.permissions,
            "tool_access": a.tool_access,
            "scope": a.scope,
            "enabled": a.enabled,
            "runs": db.query(AgentRun).filter(AgentRun.agent_id == a.id).count(),
        }
        for a in agents
    ]


@router.get("/agents/{agent_id}/runs")
def agent_runs(agent_id: str, ctx: RequestContext = Depends(require_org), db: Session = Depends(get_db)):
    check_permission(ctx.user, "system:read")
    runs = (
        db.query(AgentRun)
        .filter(AgentRun.agent_id == agent_id, (AgentRun.org_id == ctx.org.id) | (AgentRun.org_id.is_(None)))
        .order_by(AgentRun.created_at.desc())
        .limit(50)
        .all()
    )
    return [
        {
            "id": r.id,
            "status": r.status,
            "input": r.input,
            "output": r.output,
            "error": r.error,
            "model": r.model,
            "prompt_version": r.prompt_version,
            "created_at": r.created_at.isoformat(),
        }
        for r in runs
    ]


# ---------- Search ----------

@router.get("/search")
def global_search(
    q: str = Query(min_length=2),
    ctx: RequestContext = Depends(require_org),
    db: Session = Depends(get_db),
):
    check_permission(ctx.user, "assets:read")
    like = f"%{q}%"
    results: dict = {"assets": [], "findings": [], "incidents": [], "engagements": [], "users": []}
    if "assets:read" in _perms(ctx.user.role):
        results["assets"] = [
            {"id": a.id, "name": a.name, "type": a.asset_type, "ip": a.ip_address}
            for a in db.query(Asset).filter(Asset.org_id == ctx.org.id, (Asset.name.ilike(like)) | (Asset.ip_address.ilike(like)) | (Asset.dns_name.ilike(like))).limit(8).all()
        ]
    if "findings:read" in _perms(ctx.user.role):
        results["findings"] = [
            {"id": f.id, "title": f.title, "severity": f.severity}
            for f in db.query(Finding).filter(Finding.org_id == ctx.org.id, (Finding.title.ilike(like)) | (Finding.cve.ilike(like)) | (Finding.cwe.ilike(like))).limit(8).all()
        ]
    if "incidents:read" in _perms(ctx.user.role):
        results["incidents"] = [
            {"id": i.id, "title": i.title, "severity": i.severity, "status": i.status}
            for i in db.query(Incident).filter(Incident.org_id == ctx.org.id, Incident.title.ilike(like)).limit(8).all()
        ]
    if "engagements:read" in _perms(ctx.user.role):
        results["engagements"] = [
            {"id": e.id, "name": e.name, "status": e.status}
            for e in db.query(Engagement).filter(Engagement.org_id == ctx.org.id, Engagement.name.ilike(like)).limit(5).all()
        ]
    return results


def _perms(role: str) -> set[str]:
    from ..security.rbac import ROLE_PERMISSIONS

    return ROLE_PERMISSIONS.get(role, set())


# ---------- System ----------

@router.get("/system/status")
def system_status(ctx: RequestContext = Depends(get_request_context), db: Session = Depends(get_db)):
    check_permission(ctx.user, "system:read")
    from ..integrations import get_registry

    from ..models import Event, Job, Retest

    open_incidents = db.query(Incident).filter(Incident.org_id == ctx.org.id, Incident.status.in_(["OPEN", "INVESTIGATING", "CONTAINED"])).count()
    return {
        "version": settings.API_VERSION,
        "build": settings.BUILD,
        "git_revision": settings.GIT_REVISION,
        "environment": settings.ENVIRONMENT,
        "components": {
            "api": {"health": "OK"},
            "database": {"health": "OK", "detail": settings.DATABASE_URL.split(":")[0]},
            "redis": {"health": "NOT_CONFIGURED" if not settings.REDIS_URL else "OK"},
            "opensearch": {"health": "NOT_CONFIGURED" if not settings.OPENSEARCH_URL else "OK"},
            "workers": {"health": "OK", "detail": "DB-poll worker"},
            "ai": {"health": "OK", "detail": f"provider={settings.AI_PROVIDER} model={settings.AI_MODEL}"},
            "tools": get_registry().health_snapshot(),
        },
        "stats": {
            "open_incidents": open_incidents,
            "events": db.query(Event).filter(Event.org_id == ctx.org.id).count(),
            "retests": db.query(Retest).filter(Retest.org_id == ctx.org.id).count(),
        },
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/system/metrics")
def system_metrics(ctx: RequestContext = Depends(get_request_context), db: Session = Depends(get_db)):
    check_permission(ctx.user, "system:read")
    from ..models import Event, Job, Retest

    job_counts = dict(db.query(Job.status, func.count(Job.id)).filter(Job.org_id == ctx.org.id).group_by(Job.status).all())
    return {
        "jobs_by_status": job_counts,
        "events_ingested": db.query(Event).filter(Event.org_id == ctx.org.id).count(),
        "retests": db.query(Retest).filter(Retest.org_id == ctx.org.id).count(),
        "agents": db.query(AgentRun).filter((AgentRun.org_id == ctx.org.id) | (AgentRun.org_id.is_(None))).count(),
    }


@router.get("/organizations/current", response_model=OrganizationOut)
def current_org(ctx: RequestContext = Depends(require_org)):
    return ctx.org
