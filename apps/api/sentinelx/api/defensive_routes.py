"""/events, /detections, /incidents, /hunts, /playbooks, /responses routes."""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import (
    DetectionRule,
    Event,
    Incident,
    IncidentTimelineEntry,
    Playbook,
    ResponseAction,
)
from ..schemas import (
    ApprovalRequest,
    DetectionRuleCreate,
    DetectionRuleOut,
    EventCreate,
    EventOut,
    IncidentCreate,
    IncidentOut,
    IncidentUpdate,
    PlaybookCreate,
    PlaybookOut,
    ResponseActionCreate,
    ResponseActionOut,
    TimelineEntryOut,
)
from ..services.ai import analyze_incident
from ..services.events import ingest_events
from ..services.incidents import add_timeline, correlate_finding, update_status
from ..services.notifications import notify
from .deps import (
    RequestContext,
    check_permission,
    ctx_audit,
    get_request_context,
    paginate,
    require_org,
)

router = APIRouter(tags=["defensive"])

ACTION_RISK_LEVEL = {"LOW": "LOW", "MEDIUM": "MEDIUM", "HIGH": "HIGH", "CRITICAL": "CRITICAL"}
ACTION_APPROVAL_REQUIRED = {"HIGH": True, "CRITICAL": True}


# ---------- Events ----------

@router.get("/events", response_model=list[EventOut])
def list_events(
    ctx: RequestContext = Depends(require_org),
    db: Session = Depends(get_db),
    event_type: str | None = None,
    severity: str | None = None,
    source: str | None = None,
    page: int = Query(1, ge=1),
    size: int = Query(100, ge=1, le=500),
):
    check_permission(ctx.user, "events:read")
    q = db.query(Event).filter(Event.org_id == ctx.org.id)
    if event_type:
        q = q.filter(Event.event_type == event_type)
    if severity:
        q = q.filter(Event.severity == severity)
    if source:
        q = q.filter(Event.source == source)
    return paginate(q.order_by(Event.timestamp.desc()), page, size)


@router.post("/events", response_model=dict)
def ingest(body: EventCreate, ctx: RequestContext = Depends(get_request_context), db: Session = Depends(get_db)):
    """Ingest a single normalized security event (sensor → SIEM pipeline)."""
    check_permission(ctx.user, "events:ingest")
    from ..integrations.base import NormalizedEvent

    persisted, detections = ingest_events(
        db, ctx.org.id, [NormalizedEvent(event_type=body.event_type, severity=body.severity, timestamp=body.timestamp, asset_ip=None, user=body.user_id, metadata={**body.metadata, "event_id": body.event_id, "asset_id": body.asset_id})],
        source=body.source,
    )
    return {"persisted": persisted, "detections": detections}


@router.get("/events/feed", response_model=list[EventOut])
def event_feed(ctx: RequestContext = Depends(require_org), db: Session = Depends(get_db), limit: int = Query(50, ge=1, le=200)):
    check_permission(ctx.user, "events:read")
    return db.query(Event).filter(Event.org_id == ctx.org.id).order_by(Event.timestamp.desc()).limit(limit).all()


# ---------- Detection Rules ----------

@router.get("/detections/rules", response_model=list[DetectionRuleOut])
def list_rules(ctx: RequestContext = Depends(require_org), db: Session = Depends(get_db)):
    check_permission(ctx.user, "rules:read")
    return db.query(DetectionRule).filter(DetectionRule.org_id == ctx.org.id).order_by(DetectionRule.created_at.desc()).all()


@router.post("/detections/rules", response_model=DetectionRuleOut)
def create_rule(body: DetectionRuleCreate, ctx: RequestContext = Depends(require_org), db: Session = Depends(get_db)):
    check_permission(ctx.user, "rules:write")
    exists = db.query(DetectionRule).filter(DetectionRule.org_id == ctx.org.id, DetectionRule.rule_id == body.rule_id).first()
    if exists:
        raise HTTPException(status_code=409, detail="Rule ID already exists")
    rule = DetectionRule(org_id=ctx.org.id, created_by=ctx.user.id, **body.model_dump())
    db.add(rule)
    db.commit()
    db.refresh(rule)
    ctx_audit(ctx, "rule.create", resource_type="detection_rule", resource_id=rule.id, detail={"rule_id": rule.rule_id, "status": rule.status})
    return rule


@router.patch("/detections/rules/{rule_id}", response_model=DetectionRuleOut)
def update_rule(rule_id: str, body: dict, ctx: RequestContext = Depends(require_org), db: Session = Depends(get_db)):
    check_permission(ctx.user, "rules:write")
    rule = db.query(DetectionRule).filter(DetectionRule.id == rule_id, DetectionRule.org_id == ctx.org.id).first()
    if rule is None:
        raise HTTPException(status_code=404, detail="Rule not found")
    if "status" in body and body["status"] in {"DRAFT", "TEST", "DEPLOYED", "DISABLED"}:
        rule.status = body["status"]
        rule.version = rule.version + 1
    if "logic" in body:
        rule.logic = body["logic"]
        rule.version = rule.version + 1
    if "severity" in body:
        rule.severity = body["severity"]
    db.commit()
    db.refresh(rule)
    ctx_audit(ctx, "rule.update", resource_type="detection_rule", resource_id=rule.id, detail=body)
    return rule


# ---------- Incidents ----------

def _get_incident(db: Session, ctx: RequestContext, incident_id: str) -> Incident:
    inc = db.query(Incident).filter(Incident.id == incident_id, Incident.org_id == ctx.org.id).first()
    if inc is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return inc


@router.get("/incidents", response_model=list[IncidentOut])
def list_incidents(
    ctx: RequestContext = Depends(require_org),
    db: Session = Depends(get_db),
    status: str | None = None,
    severity: str | None = None,
):
    check_permission(ctx.user, "incidents:read")
    q = db.query(Incident).filter(Incident.org_id == ctx.org.id)
    if status:
        q = q.filter(Incident.status == status.upper())
    if severity:
        q = q.filter(Incident.severity == severity)
    return q.order_by(Incident.created_at.desc()).all()


@router.post("/incidents", response_model=IncidentOut)
def create_incident(body: IncidentCreate, ctx: RequestContext = Depends(require_org), db: Session = Depends(get_db)):
    check_permission(ctx.user, "incidents:write")
    inc = Incident(org_id=ctx.org.id, **body.model_dump())
    db.add(inc)
    db.flush()
    add_timeline(db, inc, kind="OBSERVATION", message="Incident created")
    db.commit()
    db.refresh(inc)
    notify(db, org_id=ctx.org.id, kind="incident", title=f"Incident {inc.id} opened", body=inc.title, link=f"/incidents/{inc.id}")
    ctx_audit(ctx, "incident.create", resource_type="incident", resource_id=inc.id, detail={"severity": inc.severity})
    return inc


@router.get("/incidents/{incident_id}", response_model=IncidentOut)
def get_incident(incident_id: str, ctx: RequestContext = Depends(require_org), db: Session = Depends(get_db)):
    check_permission(ctx.user, "incidents:read")
    return _get_incident(db, ctx, incident_id)


@router.patch("/incidents/{incident_id}", response_model=IncidentOut)
def update_incident(incident_id: str, body: IncidentUpdate, ctx: RequestContext = Depends(require_org), db: Session = Depends(get_db)):
    check_permission(ctx.user, "incidents:write")
    inc = _get_incident(db, ctx, incident_id)
    for key, value in body.model_dump(exclude_none=True).items():
        setattr(inc, key, value)
    inc.updated_at = datetime.now(timezone.utc)
    if inc.status in {"CLOSED", "RESOLVED"} and inc.closed_at is None:
        inc.closed_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(inc)
    ctx_audit(ctx, "incident.update", resource_type="incident", resource_id=inc.id, detail=body.model_dump(exclude_none=True))
    return inc


@router.get("/incidents/{incident_id}/timeline", response_model=list[TimelineEntryOut])
def incident_timeline(incident_id: str, ctx: RequestContext = Depends(require_org), db: Session = Depends(get_db)):
    check_permission(ctx.user, "incidents:read")
    inc = _get_incident(db, ctx, incident_id)
    from ..services.incidents import rebuild_timeline_from_events

    return rebuild_timeline_from_events(db, inc)


@router.post("/incidents/{incident_id}/timeline", response_model=TimelineEntryOut)
def add_timeline_entry(incident_id: str, body: dict, ctx: RequestContext = Depends(require_org), db: Session = Depends(get_db)):
    check_permission(ctx.user, "incidents:write")
    inc = _get_incident(db, ctx, incident_id)
    entry = add_timeline(
        db, inc, kind=body.get("kind", "OBSERVATION"), message=body.get("message", ""),
        source=body.get("source"), event_id=body.get("event_id"),
    )
    ctx_audit(ctx, "incident.timeline.add", resource_type="incident", resource_id=inc.id, detail={"message": entry.message})
    return entry


@router.post("/incidents/{incident_id}/analyze")
def analyze(incident_id: str, ctx: RequestContext = Depends(require_org), db: Session = Depends(get_db)):
    check_permission(ctx.user, "incidents:read")
    inc = _get_incident(db, ctx, incident_id)
    analysis = analyze_incident(db, inc)
    ctx_audit(ctx, "incident.ai_analyze", resource_type="incident", resource_id=inc.id)
    return analysis


@router.post("/incidents/{incident_id}/link-finding")
def link_finding(incident_id: str, body: dict, ctx: RequestContext = Depends(require_org), db: Session = Depends(get_db)):
    check_permission(ctx.user, "incidents:write")
    inc = _get_incident(db, ctx, incident_id)
    finding_id = body.get("finding_id")
    if not finding_id:
        raise HTTPException(status_code=400, detail="finding_id required")
    correlate_finding(db, inc, finding_id)
    add_timeline(db, inc, kind="OBSERVATION", message=f"Linked to finding {finding_id}")
    return {"ok": True, "incident_id": inc.id, "finding_id": finding_id}


# ---------- Threat Hunting ----------

@router.post("/hunts")
def run_hunt(body: dict, ctx: RequestContext = Depends(require_org), db: Session = Depends(get_db)):
    """Translate a validated natural-language hunt request into a constrained
    query plan. Only pre-approved query templates execute — never free-form
    SQL from user or AI input."""
    check_permission(ctx.user, "hunts:run")
    query = (body.get("query") or "").strip().lower()
    allowed_templates = {
        "suspicious authentication": ("auth", "authentication"),
        "new outbound": ("network", "connection"),
        "process": ("process", "process"),
        "privilege": ("auth", "privilege"),
        "rare network": ("network", "network"),
        "external": ("network", "external"),
        "data access": ("data", "data"),
        "api": ("web", "api"),
    }
    template = next((k for k, v in allowed_templates.items() if k in query), None)
    if template is None:
        return {
            "ok": False,
            "reason": "Hunt query did not match an allowed template. Supported: " + ", ".join(allowed_templates),
            "plan": None,
        }
    source_hint, type_hint = allowed_templates[template]
    events = (
        db.query(Event)
        .filter(Event.org_id == ctx.org.id)
        .order_by(Event.timestamp.desc())
        .limit(500)
        .all()
    )
    filtered = [e for e in events if type_hint in (e.event_type or "")]
    ctx_audit(ctx, "hunt.run", resource_type="hunt", detail={"template": template, "matched": len(filtered)})
    return {
        "ok": True,
        "template": template,
        "plan": {
            "source_hint": source_hint,
            "event_type_hint": type_hint,
            "limit": 500,
            "note": "Constrained to approved query templates; no free-form database queries.",
        },
        "results": [
            {
                "event_id": e.id,
                "timestamp": e.timestamp.isoformat(),
                "source": e.source,
                "event_type": e.event_type,
                "severity": e.severity,
                "asset_id": e.asset_id,
                "metadata": e.metadata_json,
            }
            for e in filtered[:100]
        ],
        "total_matches": len(filtered),
    }


# ---------- Playbooks & Response ----------

@router.get("/playbooks", response_model=list[PlaybookOut])
def list_playbooks(ctx: RequestContext = Depends(require_org), db: Session = Depends(get_db)):
    check_permission(ctx.user, "playbooks:read")
    return db.query(Playbook).filter(Playbook.org_id == ctx.org.id).all()


@router.post("/playbooks", response_model=PlaybookOut)
def create_playbook(body: PlaybookCreate, ctx: RequestContext = Depends(require_org), db: Session = Depends(get_db)):
    check_permission(ctx.user, "playbooks:write")
    pb = Playbook(org_id=ctx.org.id, name=body.name, description=body.description, triggers=body.triggers)
    db.add(pb)
    db.commit()
    db.refresh(pb)
    ctx_audit(ctx, "playbook.create", resource_type="playbook", resource_id=pb.id)
    return pb


@router.post("/playbooks/{playbook_id}/actions", response_model=ResponseActionOut)
def create_action(playbook_id: str, body: ResponseActionCreate, ctx: RequestContext = Depends(require_org), db: Session = Depends(get_db)):
    check_permission(ctx.user, "responses:write")
    pb = db.query(Playbook).filter(Playbook.id == playbook_id, Playbook.org_id == ctx.org.id).first()
    if pb is None:
        raise HTTPException(status_code=404, detail="Playbook not found")
    risk = body.risk_level.upper()
    requires_approval = body.requires_approval or ACTION_APPROVAL_REQUIRED.get(risk, False)
    action = ResponseAction(
        org_id=ctx.org.id, playbook_id=pb.id, incident_id=body.incident_id, name=body.name,
        risk_level=risk, action_type=body.action_type, target=body.target,
        requires_approval=requires_approval, status="PENDING_APPROVAL" if requires_approval else "EXECUTING",
    )
    db.add(action)
    db.commit()
    db.refresh(action)
    if action.incident_id:
        inc = db.get(Incident, action.incident_id)
        if inc:
            add_timeline(db, inc, kind="RESPONSE", message=f"Action '{action.name}' created ({action.status})")
    ctx_audit(ctx, "response.create", resource_type="response_action", resource_id=action.id, detail={"risk": risk, "action_type": body.action_type})
    return action


@router.get("/responses/actions", response_model=list[ResponseActionOut])
def list_actions(ctx: RequestContext = Depends(require_org), db: Session = Depends(get_db)):
    check_permission(ctx.user, "responses:read")
    return db.query(ResponseAction).filter(ResponseAction.org_id == ctx.org.id).order_by(ResponseAction.created_at.desc()).all()


@router.post("/responses/actions/{action_id}/approve", response_model=ResponseActionOut)
def approve_action(action_id: str, body: ApprovalRequest, ctx: RequestContext = Depends(require_org), db: Session = Depends(get_db)):
    check_permission(ctx.user, "responses:approve")
    action = db.query(ResponseAction).filter(ResponseAction.id == action_id, ResponseAction.org_id == ctx.org.id).first()
    if action is None:
        raise HTTPException(status_code=404, detail="Action not found")
    if action.status != "PENDING_APPROVAL":
        raise HTTPException(status_code=409, detail="Action is not awaiting approval")
    if body.approve:
        action.status = "APPROVED"
        action.approved_by = ctx.user.id
        action.approved_at = datetime.now(timezone.utc)
    else:
        action.status = "REJECTED"
    db.commit()
    db.refresh(action)
    if action.incident_id:
        inc = db.get(Incident, action.incident_id)
        if inc:
            add_timeline(db, inc, kind="RESPONSE", message=f"Action '{action.name}' {'approved' if body.approve else 'rejected'}")
    ctx_audit(ctx, "response.approve", resource_type="response_action", resource_id=action.id, detail={"approve": body.approve, "note": body.note})
    return action


@router.post("/responses/actions/{action_id}/execute", response_model=ResponseActionOut)
def execute_action(action_id: str, ctx: RequestContext = Depends(require_org), db: Session = Depends(get_db)):
    """Execute an approved response action through an adapter.

    Actions never run raw commands — each action_type maps to a controlled
    adapter behavior (ticket creation, monitoring enablement, session
    revocation, endpoint isolation, network block).
    """
    check_permission(ctx.user, "responses:write")
    action = db.query(ResponseAction).filter(ResponseAction.id == action_id, ResponseAction.org_id == ctx.org.id).first()
    if action is None:
        raise HTTPException(status_code=404, detail="Action not found")
    if action.requires_approval and action.status != "APPROVED":
        raise HTTPException(status_code=409, detail="Action requires approval before execution")
    if action.status == "EXECUTED":
        raise HTTPException(status_code=409, detail="Action already executed")

    from ..services.response_adapters import execute_response_action

    result = execute_response_action(db, action, actor=ctx.user.id)
    db.refresh(action)
    if action.incident_id:
        inc = db.get(Incident, action.incident_id)
        if inc:
            mode = result.get("mode", "simulated")
            state_changed = bool(result.get("state_changed"))
            add_timeline(db, inc, kind="RESPONSE", message=f"Action '{action.name}' executed [{mode}]: {result.get('summary', '')}")
            # No false success: only a measured real state change marks the
            # incident contained.
            if mode == "real" and state_changed:
                update_status(db, inc, "CONTAINED", message=f"Containment verified via '{action.name}' (before/after measured)")
            elif mode == "simulated":
                add_timeline(db, inc, kind="RESPONSE", message="Action recorded as SIMULATED — incident NOT marked contained")
            elif mode == "failed":
                add_timeline(db, inc, kind="RESPONSE", message="Action FAILED — no state change")
    ctx_audit(ctx, "response.execute", resource_type="response_action", resource_id=action.id, detail={"action_type": action.action_type, "mode": result.get("mode"), "state_changed": result.get("state_changed"), "result": result.get("summary")})
    return action
