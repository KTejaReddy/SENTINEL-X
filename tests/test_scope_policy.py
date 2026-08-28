"""Scope engine, policy engine and tool-adapter boundary regression tests.

These encode the non-negotiable authorization boundary:
  - an invalid target must never reach a tool adapter
  - destructive actions require explicit policy permission
  - rate limits are enforced per engagement
"""
from __future__ import annotations

import pytest

from sentinelx.db import SessionLocal
from sentinelx.models import Asset, Engagement, ScopeRule
from sentinelx.services.policy_engine import evaluate_policy
from sentinelx.services.scope_engine import evaluate_scope


@pytest.fixture()
def engagement():
    db = SessionLocal()
    org = db.query(Asset).first().org_id
    eng = Engagement(
        org_id=org, name="Test ENG", status="APPROVED",
        config={"allowed_tools": ["nmap"], "max_request_rate": 50, "destructive_testing": False},
    )
    db.add(eng)
    db.flush()
    db.add(ScopeRule(org_id=org, engagement_id=eng.id, kind="INCLUDE", match_type="CIDR", value="10.10.10.0/24"))
    db.add(ScopeRule(org_id=org, engagement_id=eng.id, kind="EXCLUDE", match_type="IP", value="10.10.10.20"))
    db.commit()
    db.refresh(eng)
    yield eng
    db.delete(eng)
    db.commit()
    db.close()


def test_scope_allows_in_scope_target(engagement):
    db = SessionLocal()
    decision = evaluate_scope(db, engagement, "10.10.10.10")
    assert decision.allowed is True


def test_scope_rejects_out_of_scope_target(engagement):
    db = SessionLocal()
    decision = evaluate_scope(db, engagement, "8.8.8.8")
    assert decision.allowed is False
    assert "not within" in decision.reason


def test_scope_rejects_arbitrary_domain(engagement):
    db = SessionLocal()
    decision = evaluate_scope(db, engagement, "evil.example.com")
    assert decision.allowed is False


def test_scope_exclude_rule_wins(engagement):
    db = SessionLocal()
    decision = evaluate_scope(db, engagement, "10.10.10.20")
    assert decision.allowed is False
    assert "excluded" in decision.reason


def test_scope_rejects_draft_engagement():
    db = SessionLocal()
    org = db.query(Asset).first().org_id
    draft = Engagement(org_id=org, name="Draft", status="DRAFT", config={})
    db.add(draft)
    db.flush()
    db.add(ScopeRule(org_id=org, engagement_id=draft.id, kind="INCLUDE", match_type="CIDR", value="10.10.10.0/24"))
    db.commit()
    decision = evaluate_scope(db, draft, "10.10.10.10")
    assert decision.allowed is False
    assert "status" in decision.reason


def test_policy_rejects_unknown_tool(engagement):
    db = SessionLocal()
    decision = evaluate_policy(db, engagement=engagement, target_ref="10.10.10.10", tool="not-a-tool", action="scan")
    assert decision.allowed is False
    assert "allowed_tools" in decision.reason


def test_policy_blocks_destructive_without_permission(engagement):
    db = SessionLocal()
    decision = evaluate_policy(
        db, engagement=engagement, target_ref="10.10.10.10", tool="nmap",
        action="exploit_destructive",
    )
    assert decision.allowed is False
    assert "destructive" in decision.reason.lower()


def test_policy_requires_approval_for_validation(engagement):
    db = SessionLocal()
    decision = evaluate_policy(
        db, engagement=engagement, target_ref="10.10.10.10", tool="nmap", action="validate"
    )
    assert decision.allowed is True
    assert decision.requires_approval is True


def test_policy_rate_limit_enforced():
    from datetime import datetime, timedelta, timezone

    from sentinelx.models import Job

    db = SessionLocal()
    org = db.query(Asset).first().org_id
    eng = Engagement(
        org_id=org, name="Rate ENG", status="RUNNING",
        config={"allowed_tools": ["nmap"], "max_request_rate": 2, "destructive_testing": False},
    )
    db.add(eng)
    db.flush()
    db.add(ScopeRule(org_id=org, engagement_id=eng.id, kind="INCLUDE", match_type="CIDR", value="10.10.10.0/24"))
    now = datetime.now(timezone.utc)
    for i in range(3):
        db.add(Job(org_id=org, engagement_id=eng.id, kind="scan", tool="nmap", status="completed",
                   created_at=now - timedelta(seconds=10 * i)))
    db.commit()
    decision = evaluate_policy(db, engagement=eng, target_ref="10.10.10.10", tool="nmap", action="scan")
    assert decision.allowed is False
    assert "rate limit" in decision.reason.lower()


def test_ai_action_rejects_out_of_scope_target():
    """An AI agent must not be able to request an action on an arbitrary target."""
    from sentinelx.models import Engagement as E
    from sentinelx.schemas import AIActionRequest
    from sentinelx.services.ai import evaluate_ai_action

    db = SessionLocal()
    org = db.query(Asset).first().org_id
    eng = db.query(E).filter(E.org_id == org).first()
    request = AIActionRequest(
        action="create_validation_job",
        target_id="8.8.8.8",  # arbitrary external host, not an asset
        objective="prove impact",
        engagement_id=eng.id,
    )
    result = evaluate_ai_action(db, org, request, engagement_id=eng.id)
    assert result.allowed is False


def test_ai_action_unsupported_action_rejected():
    from sentinelx.models import Engagement as E
    from sentinelx.schemas import AIActionRequest
    from sentinelx.services.ai import evaluate_ai_action

    db = SessionLocal()
    org = db.query(Asset).first().org_id
    request = AIActionRequest(action="run_arbitrary_shell", target_id="x", objective="")
    result = evaluate_ai_action(db, org, request, engagement_id=None)
    assert result.allowed is False
    assert "Unsupported" in result.reason


def test_lab_adapter_refuses_outside_lab():
    """The lab-range adapter is hard-wired to refuse anything outside the lab CIDR."""
    from sentinelx.integrations import get_registry
    from sentinelx.integrations.base import AdapterError
    from sentinelx.models import Engagement as E

    db = SessionLocal()
    org = db.query(Asset).first().org_id
    eng = db.query(E).filter(E.org_id == org).first()
    adapter = get_registry().get("lab-range")
    with pytest.raises(AdapterError):
        adapter.validate_scope(db, eng, "8.8.8.8")
