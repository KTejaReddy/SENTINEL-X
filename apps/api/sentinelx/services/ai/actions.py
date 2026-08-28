"""AI Action Validation.

An AI agent may never act directly. It proposes a structured action which is
validated against the Pydantic schema AND the scope/policy engines. Malformed,
unsupported, or out-of-scope actions are rejected before anything executes.
"""
from __future__ import annotations

from sqlalchemy.orm import Session

from ...models import Asset, Engagement, Finding
from ...schemas import AIActionRequest, AIActionResponse
from ..policy_engine import evaluate_policy
from ..scope_engine import evaluate_scope

SUPPORTED_ACTIONS = {"create_validation_job", "create_scan_job", "run_retest", "create_detection_rule", "none"}


def evaluate_ai_action(
    db: Session,
    org_id: str,
    request: AIActionRequest,
    engagement_id: str | None = None,
) -> AIActionResponse:
    if request.action not in SUPPORTED_ACTIONS:
        return AIActionResponse(
            action=request.action,
            target_id=request.target_id,
            objective=request.objective,
            confidence=request.confidence,
            requires_approval=True,
            allowed=False,
            reason=f"Unsupported action '{request.action}' — AI agents may only request supported structured actions.",
        )

    if request.action == "none":
        return AIActionResponse(action="none", target_id="", objective="", confidence=0.5, requires_approval=False, allowed=True, reason="No action requested")

    # Resolve target
    target = db.get(Asset, request.target_id)
    if target is None:
        target = db.get(Finding, request.target_id)
    if target is None:
        return AIActionResponse(
            action=request.action, target_id=request.target_id, objective=request.objective,
            confidence=request.confidence, requires_approval=True, allowed=False,
            reason=f"Target {request.target_id} not found in this organization",
        )
    if target.org_id != org_id:
        return AIActionResponse(
            action=request.action, target_id=request.target_id, objective=request.objective,
            confidence=request.confidence, requires_approval=True, allowed=False,
            reason="Target belongs to another organization",
        )

    # Offensive actions need an engagement + scope + policy approval
    if request.action in {"create_validation_job", "create_scan_job", "run_retest"}:
        if not engagement_id:
            return AIActionResponse(
                action=request.action, target_id=request.target_id, objective=request.objective,
                confidence=request.confidence, requires_approval=True, allowed=False,
                reason="Offensive action requires an active engagement context",
            )
        engagement = db.get(Engagement, engagement_id)
        if engagement is None or engagement.org_id != org_id:
            return AIActionResponse(
                action=request.action, target_id=request.target_id, objective=request.objective,
                confidence=request.confidence, requires_approval=True, allowed=False,
                reason="Engagement not found or not in this organization",
            )
        scope = evaluate_scope(db, engagement, target_ref=target.ip_address or target.dns_name or target.id, asset=target if isinstance(target, Asset) else None)
        if not scope.allowed:
            return AIActionResponse(
                action=request.action, target_id=request.target_id, objective=request.objective,
                confidence=request.confidence, requires_approval=True, allowed=False,
                reason=f"AI action target out of scope: {scope.reason}",
            )
        tool = "lab-range" if request.action in {"create_validation_job", "run_retest"} else "nuclei"
        policy = evaluate_policy(
            db, engagement=engagement, target_ref=target.ip_address or target.dns_name or target.id,
            tool=tool, action="validate" if request.action == "create_validation_job" else "scan",
            asset_id=target.id if isinstance(target, Asset) else None, actor="ai-agent",
        )
        return AIActionResponse(
            action=request.action, target_id=request.target_id, objective=request.objective,
            confidence=request.confidence,
            requires_approval=policy.requires_approval or True,
            allowed=policy.allowed,
            reason=policy.reason,
        )

    if request.action == "create_detection_rule":
        return AIActionResponse(
            action=request.action, target_id=request.target_id, objective=request.objective,
            confidence=request.confidence, requires_approval=True, allowed=True,
            reason="Detection rule creation requires SOC approval before deployment (created as DRAFT)",
        )

    return AIActionResponse(
        action=request.action, target_id=request.target_id, objective=request.objective,
        confidence=request.confidence, requires_approval=True, allowed=False,
        reason="Action not authorized",
    )
