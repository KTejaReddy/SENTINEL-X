"""/attack-paths, /purple, /reports, /ai routes."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import Asset, Engagement, Finding, Incident, Report
from ..schemas import (
    AICopilotRequest,
    AICopilotResponse,
    AIActionRequest,
    AIActionResponse,
    AITriageRequest,
    AITriageResponse,
    AttackPathOut,
    PurpleExerciseRequest,
    PurpleExerciseResult,
)
from ..services.ai import answer_question, evaluate_ai_action, triage_finding
from ..services.attack_paths import compute_attack_paths, get_graph
from ..services.exercise import run_exercise
from ..services.reports import export_report, generate_report
from .deps import (
    RequestContext,
    check_permission,
    ctx_audit,
    get_request_context,
    require_org,
)

router = APIRouter(tags=["intelligence"])


# ---------- Attack Paths ----------

@router.get("/attack-paths", response_model=list[AttackPathOut])
def list_paths(ctx: RequestContext = Depends(require_org), db: Session = Depends(get_db)):
    check_permission(ctx.user, "attack-paths:read")
    from ..models import AttackPath

    paths = db.query(AttackPath).filter(AttackPath.org_id == ctx.org.id).order_by(AttackPath.risk_score.desc()).all()
    for p in paths:
        p.nodes = sorted(p.nodes, key=lambda n: n.ordinal)
    return paths


@router.post("/attack-paths/compute", response_model=list[AttackPathOut])
def compute_paths(ctx: RequestContext = Depends(require_org), db: Session = Depends(get_db)):
    check_permission(ctx.user, "attack-paths:read")
    paths = compute_attack_paths(db, ctx.org.id)
    for p in paths:
        p.nodes = sorted(p.nodes, key=lambda n: n.ordinal)
    ctx_audit(ctx, "attack_path.compute", resource_type="org", resource_id=ctx.org.id, detail={"paths": len(paths)})
    return paths


@router.get("/attack-graph")
def graph(ctx: RequestContext = Depends(require_org), db: Session = Depends(get_db)):
    check_permission(ctx.user, "attack-paths:read")
    return get_graph(db, ctx.org.id)


# ---------- Purple Team ----------

@router.get("/purple/coverage")
def purple_coverage(ctx: RequestContext = Depends(require_org), db: Session = Depends(get_db)):
    check_permission(ctx.user, "purple:read")
    from ..services.purple import coverage_summary

    return coverage_summary(db, ctx.org.id)


@router.post("/purple/exercise", response_model=PurpleExerciseResult)
def purple_exercise(body: PurpleExerciseRequest, ctx: RequestContext = Depends(require_org), db: Session = Depends(get_db)):
    """Run a controlled purple exercise: replay a lab scenario, measure which
    stages were detected, and produce detection recommendations for gaps."""
    check_permission(ctx.user, "purple:write")
    from ..integrations.adapters.lab_range import SCENARIOS
    from ..services.purple import compute_coverage, create_gap_recommendations

    eng = db.query(Engagement).filter(Engagement.id == body.engagement_id, Engagement.org_id == ctx.org.id).first()
    if eng is None:
        raise HTTPException(status_code=404, detail="Engagement not found")
    if eng.status not in {"APPROVED", "RUNNING"}:
        raise HTTPException(status_code=409, detail="Engagement must be APPROVED or RUNNING")

    scenario = SCENARIOS.get(body.scenario)
    if scenario is None:
        raise HTTPException(status_code=400, detail=f"Unknown scenario: {body.scenario}")

    from ..services.jobs import enqueue_job
    from ..services.scope_engine import list_in_scope_assets

    # Target a concrete in-scope host, not the scope CIDR string itself, so the
    # scope/policy gate can resolve the candidate against the rules.
    in_scope = list_in_scope_assets(db, eng)
    lab_target = next((a for a in in_scope if (a.ip_address or "").startswith("10.10.10.")), in_scope[0] if in_scope else None)
    target_ref = lab_target.ip_address or lab_target.id if lab_target else (eng.scope_rules[0].value if eng.scope_rules else None)

    job = enqueue_job(
        db, org_id=ctx.org.id, engagement_id=eng.id, kind="purple", tool="lab-range",
        target_ref=target_ref,
        params={"scenario": body.scenario}, created_by=ctx.user.id, demo=True,
    )
    ctx_audit(ctx, "purple.exercise.run", resource_type="engagement", resource_id=eng.id, detail={"scenario": body.scenario, "job_id": job.id})
    return PurpleExerciseResult(
        exercise_id=job.id,
        scenario=body.scenario,
        stages=[],
        coverage={"status": "running", "job_id": job.id},
        gaps=[],
        recommendations=["Coverage will be computed when the exercise job completes."],
        demo=True,
    )


@router.get("/purple/results")
def purple_results(ctx: RequestContext = Depends(require_org), db: Session = Depends(get_db)):
    """Coverage results from completed lab exercises (job results)."""
    check_permission(ctx.user, "purple:read")
    from ..models import Job

    jobs = (
        db.query(Job)
        .filter(Job.org_id == ctx.org.id, Job.kind == "purple", Job.status == "completed")
        .order_by(Job.finished_at.desc())
        .limit(20)
        .all()
    )
    return [
        {
            "job_id": j.id,
            "scenario": (j.params or {}).get("scenario"),
            "finished_at": j.finished_at.isoformat() if j.finished_at else None,
            "result": j.result,
        }
        for j in jobs
    ]


# ---------- Reports ----------

@router.get("/reports")
def list_reports(ctx: RequestContext = Depends(require_org), db: Session = Depends(get_db)):
    check_permission(ctx.user, "reports:read")
    reports = db.query(Report).filter(Report.org_id == ctx.org.id).order_by(Report.generated_at.desc()).all()
    return [
        {
            "id": r.id,
            "report_type": r.report_type,
            "title": r.title,
            "status": r.status,
            "format": r.format,
            "generated_at": r.generated_at.isoformat() if r.generated_at else None,
            "created_by": r.created_by,
        }
        for r in reports
    ]


@router.post("/reports/generate")
def generate(body: dict, ctx: RequestContext = Depends(require_org), db: Session = Depends(get_db)):
    check_permission(ctx.user, "reports:generate")
    report_type = body.get("report_type", "executive")
    engagement_id = body.get("engagement_id")
    title = body.get("title")
    result = generate_report(db, ctx.org.id, report_type, engagement_id=engagement_id, created_by=ctx.user.id, title=title)
    ctx_audit(ctx, "report.generate", resource_type="report", resource_id=result["id"], detail={"report_type": report_type})
    return result


@router.get("/reports/{report_id}")
def get_report(report_id: str, ctx: RequestContext = Depends(require_org), db: Session = Depends(get_db)):
    check_permission(ctx.user, "reports:read")
    report = db.query(Report).filter(Report.id == report_id, Report.org_id == ctx.org.id).first()
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found")
    return {"id": report.id, "title": report.title, "report_type": report.report_type, "markdown": report.content.get("markdown"), "data": report.content.get("data")}


@router.get("/reports/{report_id}/export")
def export(report_id: str, fmt: str = Query("markdown"), ctx: RequestContext = Depends(require_org), db: Session = Depends(get_db)):
    check_permission(ctx.user, "reports:read")
    report = db.query(Report).filter(Report.id == report_id, Report.org_id == ctx.org.id).first()
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found")
    content, media_type, filename = export_report(report, fmt)
    from fastapi.responses import Response

    return Response(content=content, media_type=media_type, headers={"Content-Disposition": f'attachment; filename="{filename}"'})


# ---------- AI ----------

@router.post("/ai/triage", response_model=AITriageResponse)
def ai_triage(body: AITriageRequest, ctx: RequestContext = Depends(require_org), db: Session = Depends(get_db)):
    check_permission(ctx.user, "findings:read")
    finding = db.query(Finding).filter(Finding.id == body.finding_id, Finding.org_id == ctx.org.id).first()
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    result = triage_finding(db, finding)
    ctx_audit(ctx, "ai.triage", resource_type="finding", resource_id=finding.id)
    return result


@router.post("/ai/action", response_model=AIActionResponse)
def ai_action(body: AIActionRequest, ctx: RequestContext = Depends(require_org), db: Session = Depends(get_db)):
    """Validate a structured AI-proposed action against scope + policy."""
    check_permission(ctx.user, "ai:use")
    result = evaluate_ai_action(db, ctx.org.id, body, engagement_id=body.engagement_id)
    ctx_audit(ctx, "ai.action.request", resource_type="ai", resource_id=None, detail={"action": body.action, "target": body.target_id, "allowed": result.allowed, "reason": result.reason})
    return result


@router.post("/ai/copilot", response_model=AICopilotResponse)
def copilot(body: AICopilotRequest, ctx: RequestContext = Depends(require_org), db: Session = Depends(get_db)):
    check_permission(ctx.user, "ai:use")
    result = answer_question(db, ctx.org.id, body)
    ctx_audit(ctx, "ai.copilot", resource_type="ai", detail={"question": body.question[:120], "citations": len(result.citations)})
    return result


@router.post("/ai/exercise")
def controlled_exercise(body: dict, ctx: RequestContext = Depends(require_org), db: Session = Depends(get_db)):
    """RUN CONTROLLED SECURITY EXERCISE — approved lab workflow end-to-end."""
    check_permission(ctx.user, "engagements:write")
    scenario = body.get("scenario", "web_app_authorization")
    result = run_exercise(db, ctx.org.id, scenario, user=ctx.user)
    ctx_audit(ctx, "ai.exercise.run", resource_type="engagement", resource_id=result["engagement_id"], detail={"scenario": scenario})
    return result
