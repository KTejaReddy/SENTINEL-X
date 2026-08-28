"""/engagements, /jobs, /tools, /findings, /evidence, /retests routes."""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..db import get_db
from ..integrations import get_registry
from ..models import (
    Asset,
    Engagement,
    Evidence,
    Finding,
    Job,
    Remediation,
    Retest,
    ScopeRule,
    Tool,
)
from ..schemas import (
    EngagementCreate,
    EngagementOut,
    EvidenceCreate,
    EvidenceOut,
    FindingCreate,
    FindingOut,
    FindingUpdate,
    JobCreate,
    JobOut,
    RemediationCreate,
    RemediationOut,
    RetestOut,
    ScopeRuleCreate,
    ToolOut,
)
from ..services.evidence import link_evidence_to_finding, store_evidence
from ..services.findings import set_status, validate_finding
from ..services.jobs import cancel_job, enqueue_job, pause_job, resume_job, retry_job
from ..services.retest import enqueue_retest
from .deps import (
    RequestContext,
    check_permission,
    ctx_audit,
    get_request_context,
    paginate,
    require_org,
)

router = APIRouter(tags=["offensive"])


def _get_engagement(db: Session, ctx: RequestContext, engagement_id: str) -> Engagement:
    eng = db.query(Engagement).filter(Engagement.id == engagement_id, Engagement.org_id == ctx.org.id).first()
    if eng is None:
        raise HTTPException(status_code=404, detail="Engagement not found")
    return eng


# ---------- Engagements ----------

@router.get("/engagements", response_model=list[EngagementOut])
def list_engagements(
    ctx: RequestContext = Depends(require_org),
    db: Session = Depends(get_db),
    status: str | None = None,
):
    check_permission(ctx.user, "engagements:read")
    q = db.query(Engagement).filter(Engagement.org_id == ctx.org.id)
    if status:
        q = q.filter(Engagement.status == status.upper())
    return q.order_by(Engagement.created_at.desc()).all()


@router.post("/engagements", response_model=EngagementOut)
def create_engagement(body: EngagementCreate, ctx: RequestContext = Depends(require_org), db: Session = Depends(get_db)):
    check_permission(ctx.user, "engagements:write")
    eng = Engagement(
        org_id=ctx.org.id,
        name=body.name,
        description=body.description,
        status="DRAFT",
        start_date=body.start_date,
        end_date=body.end_date,
        config=body.config,
        created_by=ctx.user.id,
    )
    db.add(eng)
    db.flush()
    for rule in body.scope_rules:
        db.add(ScopeRule(org_id=ctx.org.id, engagement_id=eng.id, kind=rule.kind, match_type=rule.match_type, value=rule.value, note=rule.note))
    db.commit()
    db.refresh(eng)
    ctx_audit(ctx, "engagement.create", resource_type="engagement", resource_id=eng.id, detail={"name": eng.name})
    return eng


@router.get("/engagements/{engagement_id}", response_model=EngagementOut)
def get_engagement(engagement_id: str, ctx: RequestContext = Depends(require_org), db: Session = Depends(get_db)):
    check_permission(ctx.user, "engagements:read")
    return _get_engagement(db, ctx, engagement_id)


@router.post("/engagements/{engagement_id}/scope", response_model=EngagementOut)
def add_scope_rule(engagement_id: str, body: ScopeRuleCreate, ctx: RequestContext = Depends(require_org), db: Session = Depends(get_db)):
    check_permission(ctx.user, "engagements:write")
    eng = _get_engagement(db, ctx, engagement_id)
    if eng.status not in {"DRAFT", "PENDING_APPROVAL"}:
        raise HTTPException(status_code=409, detail="Scope can only change while DRAFT or PENDING_APPROVAL")
    db.add(ScopeRule(org_id=ctx.org.id, engagement_id=eng.id, kind=body.kind, match_type=body.match_type, value=body.value, note=body.note))
    db.commit()
    db.refresh(eng)
    ctx_audit(ctx, "engagement.scope.add", resource_type="engagement", resource_id=eng.id, detail={"kind": body.kind, "value": body.value})
    return eng


@router.post("/engagements/{engagement_id}/submit")
def submit_engagement(engagement_id: str, ctx: RequestContext = Depends(require_org), db: Session = Depends(get_db)):
    eng = _get_engagement(db, ctx, engagement_id)
    check_permission(ctx.user, "engagements:write")
    if not eng.scope_rules:
        raise HTTPException(status_code=400, detail="Engagement must define at least one scope rule before submission")
    eng.status = "PENDING_APPROVAL"
    db.commit()
    ctx_audit(ctx, "engagement.submit", resource_type="engagement", resource_id=eng.id, detail={"status": "PENDING_APPROVAL"})
    return {"ok": True, "status": eng.status}


@router.post("/engagements/{engagement_id}/approve")
def approve_engagement(engagement_id: str, ctx: RequestContext = Depends(require_org), db: Session = Depends(get_db)):
    eng = _get_engagement(db, ctx, engagement_id)
    check_permission(ctx.user, "engagements:approve")
    if eng.status != "PENDING_APPROVAL":
        raise HTTPException(status_code=409, detail="Engagement must be PENDING_APPROVAL")
    eng.status = "APPROVED"
    eng.approved_by = ctx.user.id
    eng.approved_at = datetime.now(timezone.utc)
    db.commit()
    ctx_audit(ctx, "engagement.approve", resource_type="engagement", resource_id=eng.id, detail={"approved_by": ctx.user.id})
    return {"ok": True, "status": eng.status}


@router.post("/engagements/{engagement_id}/start")
def start_engagement(engagement_id: str, ctx: RequestContext = Depends(require_org), db: Session = Depends(get_db)):
    eng = _get_engagement(db, ctx, engagement_id)
    check_permission(ctx.user, "engagements:write")
    if eng.status not in {"APPROVED", "PAUSED"}:
        raise HTTPException(status_code=409, detail="Engagement must be APPROVED or PAUSED")
    eng.status = "RUNNING"
    db.commit()
    ctx_audit(ctx, "engagement.start", resource_type="engagement", resource_id=eng.id)
    return {"ok": True, "status": eng.status}


@router.post("/engagements/{engagement_id}/pause")
def pause_engagement(engagement_id: str, ctx: RequestContext = Depends(require_org), db: Session = Depends(get_db)):
    eng = _get_engagement(db, ctx, engagement_id)
    check_permission(ctx.user, "engagements:write")
    if eng.status != "RUNNING":
        raise HTTPException(status_code=409, detail="Engagement is not RUNNING")
    eng.status = "PAUSED"
    db.commit()
    for job in db.query(Job).filter(Job.engagement_id == eng.id, Job.status == "queued").all():
        pause_job(db, job)
    ctx_audit(ctx, "engagement.pause", resource_type="engagement", resource_id=eng.id)
    return {"ok": True, "status": eng.status}


@router.post("/engagements/{engagement_id}/close")
def close_engagement(engagement_id: str, ctx: RequestContext = Depends(require_org), db: Session = Depends(get_db)):
    eng = _get_engagement(db, ctx, engagement_id)
    check_permission(ctx.user, "engagements:write")
    eng.status = "CLOSED"
    db.commit()
    for job in db.query(Job).filter(Job.engagement_id == eng.id, Job.status == "queued").all():
        cancel_job(db, job, by=ctx.user.id)
    ctx_audit(ctx, "engagement.close", resource_type="engagement", resource_id=eng.id)
    return {"ok": True, "status": eng.status}


@router.post("/engagements/{engagement_id}/check-scope")
def check_scope(engagement_id: str, body: dict, ctx: RequestContext = Depends(require_org), db: Session = Depends(get_db)):
    """Scope-engine check endpoint: verify a candidate target before running anything."""
    check_permission(ctx.user, "engagements:read")
    eng = _get_engagement(db, ctx, engagement_id)
    from ..services.scope_engine import evaluate_scope

    decision = evaluate_scope(db, eng, body.get("target"))
    return {"allowed": decision.allowed, "reason": decision.reason, "checks": decision.checks}


# ---------- Jobs ----------

@router.get("/jobs", response_model=list[JobOut])
def list_jobs(
    ctx: RequestContext = Depends(require_org),
    db: Session = Depends(get_db),
    engagement_id: str | None = None,
    status: str | None = None,
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=200),
):
    check_permission(ctx.user, "scans:read")
    q = db.query(Job).filter(Job.org_id == ctx.org.id)
    if engagement_id:
        q = q.filter(Job.engagement_id == engagement_id)
    if status:
        q = q.filter(Job.status == status)
    return paginate(q.order_by(Job.created_at.desc()), page, size)


@router.post("/jobs", response_model=JobOut)
def create_job(body: JobCreate, ctx: RequestContext = Depends(require_org), db: Session = Depends(get_db)):
    check_permission(ctx.user, "scans:run")
    eng = _get_engagement(db, ctx, body.engagement_id)
    if eng.status not in {"APPROVED", "RUNNING"}:
        raise HTTPException(status_code=409, detail="Engagement must be APPROVED or RUNNING to run jobs")
    job = enqueue_job(
        db, org_id=ctx.org.id, engagement_id=eng.id, kind=body.kind, tool=body.tool,
        target_ref=body.target_ref, params=body.params, created_by=ctx.user.id,
    )
    ctx_audit(ctx, "job.create", resource_type="job", resource_id=job.id, detail={"kind": job.kind, "tool": job.tool, "target": job.target_ref})
    return job


@router.post("/jobs/{job_id}/cancel")
def cancel(job_id: str, ctx: RequestContext = Depends(require_org), db: Session = Depends(get_db)):
    check_permission(ctx.user, "jobs:manage")
    job = db.query(Job).filter(Job.id == job_id, Job.org_id == ctx.org.id).first()
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    cancel_job(db, job, by=ctx.user.id)
    ctx_audit(ctx, "job.cancel", resource_type="job", resource_id=job.id)
    return {"ok": True, "status": job.status}


@router.post("/jobs/{job_id}/pause")
def pause(job_id: str, ctx: RequestContext = Depends(require_org), db: Session = Depends(get_db)):
    check_permission(ctx.user, "jobs:manage")
    job = db.query(Job).filter(Job.id == job_id, Job.org_id == ctx.org.id).first()
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    pause_job(db, job)
    return {"ok": True, "status": job.status}


@router.post("/jobs/{job_id}/resume")
def resume(job_id: str, ctx: RequestContext = Depends(require_org), db: Session = Depends(get_db)):
    check_permission(ctx.user, "jobs:manage")
    job = db.query(Job).filter(Job.id == job_id, Job.org_id == ctx.org.id).first()
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    resume_job(db, job)
    return {"ok": True, "status": job.status}


@router.post("/jobs/{job_id}/retry")
def retry(job_id: str, ctx: RequestContext = Depends(require_org), db: Session = Depends(get_db)):
    check_permission(ctx.user, "jobs:manage")
    job = db.query(Job).filter(Job.id == job_id, Job.org_id == ctx.org.id).first()
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    retry_job(db, job, by=ctx.user.id)
    return {"ok": True, "status": job.status}


# ---------- Tools ----------

@router.get("/tools", response_model=list[ToolOut])
def list_tools(ctx: RequestContext = Depends(require_org), db: Session = Depends(get_db)):
    check_permission(ctx.user, "tools:read")
    registry = get_registry()
    snapshot = registry.health_snapshot()
    for item in snapshot:
        tool = db.query(Tool).filter(Tool.name == item["name"]).first()
        if tool is None:
            tool = Tool(name=item["name"], category="scanner")
            db.add(tool)
        tool.installed = item["installed"]
        tool.version = item.get("version")
        tool.health = item["health"]
        tool.last_checked_at = datetime.now(timezone.utc)
        tool.metadata_json = {"description": registry.get(item["name"]).description, "category": registry.get(item["name"]).category}
    db.commit()
    return db.query(Tool).order_by(Tool.name).all()


@router.post("/tools/health-check")
def refresh_tool_health(ctx: RequestContext = Depends(require_org), db: Session = Depends(get_db)):
    check_permission(ctx.user, "tools:read")
    registry = get_registry()
    return registry.health_snapshot()


# ---------- Findings ----------

def _get_finding(db: Session, ctx: RequestContext, finding_id: str) -> Finding:
    f = db.query(Finding).filter(Finding.id == finding_id, Finding.org_id == ctx.org.id).first()
    if f is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    return f


@router.get("/findings", response_model=list[FindingOut])
def list_findings(
    ctx: RequestContext = Depends(require_org),
    db: Session = Depends(get_db),
    status: str | None = None,
    severity: str | None = None,
    asset_id: str | None = None,
    search: str | None = None,
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=200),
):
    check_permission(ctx.user, "findings:read")
    q = db.query(Finding).filter(Finding.org_id == ctx.org.id)
    if status:
        q = q.filter(Finding.status == status.upper())
    if severity:
        q = q.filter(Finding.severity == severity.upper())
    if asset_id:
        q = q.filter(Finding.asset_id == asset_id)
    if search:
        like = f"%{search}%"
        q = q.filter((Finding.title.ilike(like)) | (Finding.cve.ilike(like)) | (Finding.cwe.ilike(like)))
    rows = paginate(q, page, size)
    order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    rows.sort(key=lambda f: (order.get(f.severity.upper(), 0), f.cvss or 0), reverse=True)
    return rows


@router.post("/findings", response_model=FindingOut)
def create_finding(body: FindingCreate, ctx: RequestContext = Depends(require_org), db: Session = Depends(get_db)):
    check_permission(ctx.user, "findings:write")
    from ..services.findings import dedup_key

    payload = body.model_dump(exclude={"metadata"})
    payload["dedup_key"] = dedup_key(ctx.org.id, body.asset_id, body.endpoint, body.cve, body.cwe, body.category)
    finding = Finding(org_id=ctx.org.id, **payload)
    finding.metadata_json = body.metadata
    db.add(finding)
    db.commit()
    db.refresh(finding)
    ctx_audit(ctx, "finding.create", resource_type="finding", resource_id=finding.id, detail={"title": finding.title})
    return finding


@router.get("/findings/{finding_id}", response_model=FindingOut)
def get_finding(finding_id: str, ctx: RequestContext = Depends(require_org), db: Session = Depends(get_db)):
    check_permission(ctx.user, "findings:read")
    return _get_finding(db, ctx, finding_id)


@router.patch("/findings/{finding_id}", response_model=FindingOut)
def update_finding(finding_id: str, body: FindingUpdate, ctx: RequestContext = Depends(require_org), db: Session = Depends(get_db)):
    check_permission(ctx.user, "findings:write")
    finding = _get_finding(db, ctx, finding_id)
    for key, value in body.model_dump(exclude_none=True).items():
        if key == "risk_accepted_reason":
            finding.metadata_json = {**(finding.metadata_json or {}), "risk_accepted_reason": value}
            continue
        setattr(finding, key, value)
    finding.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(finding)
    ctx_audit(ctx, "finding.update", resource_type="finding", resource_id=finding.id, detail=body.model_dump(exclude_none=True))
    return finding


@router.post("/findings/{finding_id}/validate", response_model=FindingOut)
def validate(finding_id: str, ctx: RequestContext = Depends(require_org), db: Session = Depends(get_db)):
    """Validate a finding with a controlled test. Requires an approved engagement and scope."""
    check_permission(ctx.user, "scans:run")
    finding = _get_finding(db, ctx, finding_id)
    if not finding.engagement_id:
        raise HTTPException(status_code=400, detail="Finding has no engagement; attach it to an approved engagement first")
    eng = db.query(Engagement).filter(Engagement.id == finding.engagement_id, Engagement.org_id == ctx.org.id).first()
    if eng is None or eng.status not in {"APPROVED", "RUNNING"}:
        raise HTTPException(status_code=409, detail="Engagement must be APPROVED or RUNNING")

    from ..services.jobs import enqueue_job

    job = enqueue_job(
        db, org_id=ctx.org.id, engagement_id=eng.id, kind="validate", tool="lab-range",
        target_ref=finding.asset_id or finding.endpoint,
        params={"finding_id": finding.id, "scenario": (finding.metadata_json or {}).get("scenario", "web_app_authorization")},
        created_by=ctx.user.id, demo=finding.demo,
    )
    set_status(db, finding, "VALIDATING", reason=f"validation job {job.id} enqueued")
    ctx_audit(ctx, "finding.validate.request", resource_type="finding", resource_id=finding.id, detail={"job_id": job.id, "engagement_id": eng.id})
    return finding


@router.get("/vulnerabilities", response_model=list[FindingOut])
def vulnerabilities(ctx: RequestContext = Depends(require_org), db: Session = Depends(get_db)):
    check_permission(ctx.user, "findings:read")
    rows = (
        db.query(Finding)
        .filter(Finding.org_id == ctx.org.id, Finding.status.notin_(["CLOSED", "VERIFIED", "FIXED"]))
        .all()
    )
    order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    rows.sort(key=lambda f: (order.get(f.severity.upper(), 0), f.cvss or 0), reverse=True)
    return rows


# ---------- Evidence ----------

@router.get("/evidence", response_model=list[EvidenceOut])
def list_evidence(ctx: RequestContext = Depends(require_org), db: Session = Depends(get_db)):
    check_permission(ctx.user, "evidence:read")
    return db.query(Evidence).filter(Evidence.org_id == ctx.org.id).order_by(Evidence.created_at.desc()).limit(200).all()


@router.post("/evidence", response_model=EvidenceOut)
def create_evidence(body: EvidenceCreate, ctx: RequestContext = Depends(require_org), db: Session = Depends(get_db)):
    check_permission(ctx.user, "evidence:write")
    ev = store_evidence(
        db, org_id=ctx.org.id, finding_id=body.finding_id, incident_id=body.incident_id,
        engagement_id=body.engagement_id, kind=body.kind, data=body.data, tool=body.tool,
        captured_at=body.captured_at, created_by=ctx.user.id,
    )
    if body.finding_id:
        link_evidence_to_finding(db, body.finding_id, ev.id)
    ctx_audit(ctx, "evidence.create", resource_type="evidence", resource_id=ev.id, detail={"kind": ev.kind, "hash": ev.content_hash[:12]})
    return ev


@router.get("/evidence/{evidence_id}", response_model=EvidenceOut)
def get_evidence(evidence_id: str, ctx: RequestContext = Depends(require_org), db: Session = Depends(get_db)):
    check_permission(ctx.user, "evidence:read")
    ev = db.query(Evidence).filter(Evidence.id == evidence_id, Evidence.org_id == ctx.org.id).first()
    if ev is None:
        raise HTTPException(status_code=404, detail="Evidence not found")
    return ev


# ---------- Remediation ----------

@router.post("/remediation", response_model=RemediationOut)
def create_remediation(body: RemediationCreate, ctx: RequestContext = Depends(require_org), db: Session = Depends(get_db)):
    check_permission(ctx.user, "remediation:write")
    finding = _get_finding(db, ctx, body.finding_id)
    rem = Remediation(org_id=ctx.org.id, finding_id=finding.id, owner=body.owner, due_date=body.due_date, notes=body.notes)
    db.add(rem)
    finding.status = "REMEDIATION"
    db.commit()
    db.refresh(rem)
    ctx_audit(ctx, "remediation.create", resource_type="remediation", resource_id=rem.id, detail={"finding_id": finding.id})
    return rem


@router.get("/remediation", response_model=list[RemediationOut])
def list_remediation(ctx: RequestContext = Depends(require_org), db: Session = Depends(get_db)):
    check_permission(ctx.user, "remediation:read")
    return db.query(Remediation).filter(Remediation.org_id == ctx.org.id).order_by(Remediation.created_at.desc()).all()


@router.post("/remediation/{remediation_id}/verify")
def verify_remediation(remediation_id: str, ctx: RequestContext = Depends(require_org), db: Session = Depends(get_db)):
    check_permission(ctx.user, "remediation:write")
    rem = db.query(Remediation).filter(Remediation.id == remediation_id, Remediation.org_id == ctx.org.id).first()
    if rem is None:
        raise HTTPException(status_code=404, detail="Remediation not found")
    finding = db.get(Finding, rem.finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    from ..services.retest import enqueue_retest

    eng = db.query(Engagement).filter(Engagement.id == finding.engagement_id).first() if finding.engagement_id else None
    if eng is None:
        # Create a retest engagement for remediation verification
        eng = Engagement(
            org_id=ctx.org.id, name=f"Retest {finding.id}", status="APPROVED",
            config={"allowed_tools": ["lab-range"], "destructive_testing": False},
            approved_by=ctx.user.id, approved_at=datetime.now(timezone.utc),
        )
        db.add(eng)
        db.flush()
        db.add(ScopeRule(org_id=ctx.org.id, engagement_id=eng.id, kind="INCLUDE", match_type="CIDR", value="10.10.10.0/24"))
        db.commit()
    job = enqueue_retest(db, finding, tool="lab-range", engagement_id=eng.id, created_by=ctx.user.id)
    finding.status = "RETESTING"
    rem.status = "IN_PROGRESS"
    db.commit()
    ctx_audit(ctx, "remediation.verify", resource_type="remediation", resource_id=rem.id, detail={"retest_job": job.id})
    return rem


# ---------- Retests ----------


class RetestRequest(BaseModel):
    """Retest request. When base_url/api_base_url are provided the real DAST
    adapter re-probes the target; otherwise the controlled lab-range adapter
    is used. The retest only PASSES when a conclusive scan no longer reports
    the finding."""

    tool: str | None = None
    base_url: str | None = None
    api_base_url: str | None = None
    probe_set: str = "full"


@router.post("/findings/{finding_id}/retest", response_model=JobOut)
def retest_finding(finding_id: str, body: RetestRequest, ctx: RequestContext = Depends(require_org), db: Session = Depends(get_db)):
    """Re-run the relevant security check against the same finding."""
    check_permission(ctx.user, "retests:run")
    finding = _get_finding(db, ctx, finding_id)
    eng = db.query(Engagement).filter(Engagement.id == finding.engagement_id, Engagement.org_id == ctx.org.id).first() if finding.engagement_id else None
    if eng is None:
        raise HTTPException(status_code=400, detail="Finding has no approved engagement; attach one before retesting")
    if eng.status not in {"APPROVED", "RUNNING"}:
        raise HTTPException(status_code=409, detail="Engagement must be APPROVED or RUNNING")

    from ..services.retest import enqueue_retest

    tool = body.tool or ("dast" if (body.base_url or body.api_base_url) else "lab-range")
    extra = {}
    if body.base_url:
        extra["base_url"] = body.base_url
    if body.api_base_url:
        extra["api_base_url"] = body.api_base_url
    if extra:
        extra["probe_set"] = body.probe_set
    job = enqueue_retest(db, finding, tool=tool, engagement_id=eng.id, created_by=ctx.user.id, extra_params=extra or None)
    set_status(db, finding, "RETESTING", reason=f"retest job {job.id} enqueued")
    ctx_audit(ctx, "finding.retest.request", resource_type="finding", resource_id=finding.id, detail={"job_id": job.id, "tool": tool})
    return job


@router.get("/retests", response_model=list[RetestOut])
def list_retests(ctx: RequestContext = Depends(require_org), db: Session = Depends(get_db)):
    check_permission(ctx.user, "retests:read")
    return db.query(Retest).filter(Retest.org_id == ctx.org.id).order_by(Retest.created_at.desc()).all()
