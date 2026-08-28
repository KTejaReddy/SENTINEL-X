"""Security Policy Engine.

The policy engine is authoritative over both users and AI agents. Every
offensive or response action is checked here BEFORE any tool adapter runs.

Checks:
- engagement exists and is active
- target is inside scope (scope engine)
- tool is in the engagement's allowed-tools list
- action category is permitted (no destructive actions without policy permission)
- request rate does not exceed engagement limits
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlalchemy.orm import Session

from ..models import Engagement, Job
from .scope_engine import evaluate_scope

DESTRUCTIVE_ACTIONS = {"exploit_destructive", "data_destruction", "persistence_install", "lateral_compromise"}
APPROVAL_REQUIRED_ACTIONS = {
    "validate": True,
    "controlled_test": True,
    "exploit": True,
    "exploit_destructive": True,
    "response_high": True,
    "response_critical": True,
    "retest": False,
    "recon": False,
    "scan": False,
}


@dataclass
class PolicyDecision:
    allowed: bool
    requires_approval: bool
    reason: str
    checks: list[dict]


def _recent_request_count(db: Session, engagement_id: str, window_seconds: int = 60) -> int:
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=window_seconds)
    return (
        db.query(Job)
        .filter(Job.engagement_id == engagement_id, Job.created_at >= cutoff)
        .count()
    )


def evaluate_policy(
    db: Session,
    *,
    engagement: Engagement,
    target_ref: str | None,
    tool: str,
    action: str = "scan",
    asset_id: Optional[str] = None,
    asset: Optional[Any] = None,
    actor: str = "user",
) -> PolicyDecision:
    checks: list[dict] = []

    # 1. Active engagement
    if engagement.status not in {"APPROVED", "RUNNING"}:
        return PolicyDecision(False, False, "Engagement is not active", checks)

    # 2. Scope — pass the resolved asset so its IP/DNS/id are all considered
    scope = evaluate_scope(db, engagement, target_ref, asset=asset)
    checks.append({"check": "scope", "allowed": scope.allowed, "detail": scope.reason})
    if not scope.allowed:
        return PolicyDecision(False, False, f"Scope denied: {scope.reason}", checks)

    # 3. Allowed tools
    allowed_tools = engagement.config.get("allowed_tools") or []
    if tool not in allowed_tools and allowed_tools:
        return PolicyDecision(False, False, f"Tool '{tool}' not in engagement allowed_tools", checks)
    checks.append({"check": "tools", "allowed": True, "detail": tool})

    # 4. Destructive actions require explicit policy permission
    if action in DESTRUCTIVE_ACTIONS:
        if not engagement.config.get("destructive_testing"):
            return PolicyDecision(False, False, "Destructive testing not permitted by engagement policy", checks)

    # 5. Rate limiting
    rate = engagement.config.get("max_request_rate") or 10
    if _recent_request_count(db, engagement.id) >= rate:
        return PolicyDecision(False, False, f"Rate limit exceeded for engagement ({rate} requests/min)", checks)

    # 6. Approval requirements
    requires_approval = APPROVAL_REQUIRED_ACTIONS.get(action, True)
    checks.append({"check": "approval", "required": requires_approval, "detail": action})

    reason = f"Allowed: {action} with {tool} within authorized scope"
    return PolicyDecision(True, requires_approval, reason, checks)
