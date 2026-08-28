"""Scope Engine.

Decides whether a candidate target (IP / CIDR / hostname / domain / asset id)
is inside an engagement's authorized scope. This is the authoritative gate for
every offensive operation. Targets outside the scope are rejected before any
tool adapter is invoked.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from typing import Optional

from sqlalchemy.orm import Session

from ..models import Asset, Engagement, ScopeRule

ENGAGEMENT_ACTIVE = {"APPROVED", "RUNNING"}


@dataclass
class ScopeDecision:
    allowed: bool
    reason: str
    matched_rule: Optional[str] = None
    checks: list[dict] = field(default_factory=list)


def _candidate_values(target_ref: str | None, asset: Asset | None) -> list[str]:
    values: list[str] = []
    if target_ref:
        values.append(target_ref.strip())
    if asset:
        if asset.ip_address:
            values.append(asset.ip_address)
        if asset.dns_name:
            values.append(asset.dns_name)
        values.append(asset.id)
    return [v for v in values if v]


def _rule_matches(rule: ScopeRule, candidate: str) -> bool:
    mt = rule.match_type
    value = rule.value.strip()
    try:
        if mt == "CIDR":
            network = ipaddress.ip_network(value, strict=False)
            try:
                return ipaddress.ip_address(candidate) in network
            except ValueError:
                return False
        if mt == "IP":
            try:
                return ipaddress.ip_address(candidate) == ipaddress.ip_address(value)
            except ValueError:
                return False
        if mt == "DOMAIN":
            cand = candidate.lower().rstrip(".")
            dom = value.lower().rstrip(".")
            return cand == dom or cand.endswith("." + dom)
        if mt == "HOSTNAME":
            return candidate.lower() == value.lower()
        if mt == "ASSET":
            return candidate == value
        if mt == "EXACT":
            return candidate == value
    except ValueError:
        return False
    return False


def evaluate_scope(
    db: Session,
    engagement: Engagement,
    target_ref: str | None,
    asset: Asset | None = None,
    now: datetime | None = None,
) -> ScopeDecision:
    now = now or datetime.now(timezone.utc)
    checks: list[dict] = []

    # 1. Engagement must be active
    if engagement.status not in ENGAGEMENT_ACTIVE:
        return ScopeDecision(False, f"Engagement status is {engagement.status}; must be APPROVED or RUNNING", checks=checks)

    # 2. Testing window
    if engagement.start_date:
        if now.date() < engagement.start_date:
            return ScopeDecision(False, "Outside engagement start date", checks=checks)
    if engagement.end_date:
        if now.date() > engagement.end_date:
            return ScopeDecision(False, "Past engagement end date", checks=checks)

    candidates = _candidate_values(target_ref, asset)
    if not candidates:
        return ScopeDecision(False, "No target specified", checks=checks)

    include_rules = [r for r in engagement.scope_rules if r.kind == "INCLUDE"]
    exclude_rules = [r for r in engagement.scope_rules if r.kind == "EXCLUDE"]
    if not include_rules:
        return ScopeDecision(False, "Engagement has no INCLUDE scope rules", checks=checks)

    # 3. Exclude rules win
    for rule in exclude_rules:
        if any(_rule_matches(rule, c) for c in candidates):
            return ScopeDecision(False, f"Target excluded by scope rule {rule.value}", matched_rule=rule.id, checks=checks)

    # 4. At least one include rule must match
    matched: list[str] = []
    for rule in include_rules:
        if any(_rule_matches(rule, c) for c in candidates):
            matched.append(rule.value)
    if not matched:
        return ScopeDecision(False, "Target not within any authorized scope rule", checks=checks)

    checks.append({"target": target_ref, "matched_rules": matched})
    return ScopeDecision(True, f"Target within authorized scope ({', '.join(matched)})", matched_rule=matched[0], checks=checks)


def scope_covers(db: Session, engagement: Engagement, target_ref: str) -> ScopeDecision:
    """Convenience: scope check by raw target string."""
    return evaluate_scope(db, engagement, target_ref)


def list_in_scope_assets(db: Session, engagement: Engagement) -> list[Asset]:
    """All assets in the org whose identity matches an INCLUDE rule and no EXCLUDE rule."""
    assets = db.query(Asset).filter(Asset.org_id == engagement.org_id).all()
    result = []
    for asset in assets:
        decision = evaluate_scope(db, engagement, asset.ip_address or asset.dns_name or asset.id, asset=asset)
        if decision.allowed:
            result.append(asset)
    return result
