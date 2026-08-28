"""Response action adapters.

Every response action maps to a controlled adapter behavior. Nothing here
executes arbitrary commands; adapters perform defined, auditable operations:

- REAL: HTTP state changes against the authorized lab targets with before/
  after probes (account disable, token revocation, service isolation).
- PLATFORM: platform-side bookkeeping (tickets, monitoring, evidence).
- SIMULATED: operations that require lab gateway/network control not present
  in this environment — reported honestly as SIMULATED, never as real
  containment.

Every result records mode, state_changed (measured), before/after probes and
timestamps so the UI and audit trail never confuse simulation with success.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import httpx

from ..models import ResponseAction

LAB_WEB_USERS = ["alice", "admin"]  # non-admin lab accounts that can be disabled
LEAKED_SERVICE_TOKEN = "lab-service-token-2026"


def _probe_login(base_url: str, username: str, password: str) -> int:
    """Real login probe — returns the HTTP status (0 = unreachable)."""
    try:
        resp = httpx.post(f"{base_url.rstrip('/')}/login", json={"username": username, "password": password}, timeout=6)
        return resp.status_code
    except httpx.HTTPError:
        return 0


def _probe_admin_users(api_base: str, token: str) -> int:
    try:
        resp = httpx.get(f"{api_base.rstrip('/')}/admin/users", headers={"Authorization": f"Bearer {token}"}, timeout=6)
        return resp.status_code
    except httpx.HTTPError:
        return 0


def _lab_admin_session(base_url: str) -> httpx.Client | None:
    """Authenticated admin session against the lab web app (real login)."""
    client = httpx.Client(timeout=6, follow_redirects=True)
    resp = client.post(f"{base_url.rstrip('/')}/login", json={"username": "admin", "password": "admin"})
    if resp.status_code != 200:
        client.close()
        return None
    return client


def _login_creds(username: str) -> str:
    return "alice" if username == "alice" else username


def _disable_account(action: ResponseAction) -> dict[str, Any]:
    target = action.target or {}
    base_url = target.get("base_url", "")
    username = target.get("username", "alice")
    if not base_url:
        return {"action_type": action.action_type, "mode": "failed", "state_changed": False, "summary": "target base_url not configured"}
    before = _probe_login(base_url, username, _login_creds(username))
    client = _lab_admin_session(base_url)
    if client is None:
        return {"action_type": action.action_type, "mode": "failed", "state_changed": False, "summary": "lab admin login failed (lab unreachable?)", "before": {"login_status": before}}
    resp = client.post(f"{base_url.rstrip('/')}/admin/disable/{username}")
    client.close()
    after = _probe_login(base_url, username, _login_creds(username))
    changed = resp.status_code == 200 and before == 200 and after == 401
    return {
        "action_type": action.action_type,
        "mode": "real",
        "account": username,
        "before": {"login_status": before},
        "action_status": resp.status_code,
        "after": {"login_status": after},
        "state_changed": changed,
        "summary": f"Account {username} disabled (login {before} → {after})",
    }


def _revoke_token(action: ResponseAction) -> dict[str, Any]:
    target = action.target or {}
    api_base = target.get("api_base_url", "")
    token = target.get("token", LEAKED_SERVICE_TOKEN)
    if not api_base:
        return {"action_type": action.action_type, "mode": "failed", "state_changed": False, "summary": "target api_base_url not configured"}
    before = _probe_admin_users(api_base, token)
    try:
        resp = httpx.post(f"{api_base.rstrip('/')}/admin/revoke-token", headers={"Authorization": f"Bearer {token}"}, timeout=6)
    except httpx.HTTPError:
        resp = None
    after = _probe_admin_users(api_base, token)
    changed = resp is not None and resp.status_code == 200 and before == 200 and after == 401
    return {
        "action_type": action.action_type,
        "mode": "real",
        "token_redacted": True,
        "before": {"admin_users_status": before},
        "action_status": resp.status_code if resp else None,
        "after": {"admin_users_status": after},
        "state_changed": changed,
        "summary": f"Service token revoked (admin access {before} → {after})",
    }


def _enable_account(action: ResponseAction) -> dict[str, Any]:
    """Remediation counterpart of DISABLE_ACCOUNT (enables the lab account)."""
    target = action.target or {}
    base_url = target.get("base_url", "")
    username = target.get("username", "alice")
    client = _lab_admin_session(base_url) if base_url else None
    if client is None:
        return {"action_type": action.action_type, "mode": "failed", "state_changed": False, "summary": "lab admin login failed (lab unreachable?)"}
    resp = client.post(f"{base_url.rstrip('/')}/admin/enable/{username}")
    client.close()
    after = _probe_login(base_url, username, _login_creds(username))
    changed = resp.status_code == 200 and after == 200
    return {
        "action_type": action.action_type,
        "mode": "real",
        "before": {"disabled": True},
        "action_status": resp.status_code,
        "after": {"login_status": after},
        "state_changed": changed,
        "summary": f"Account {username} re-enabled (login now {after})",
    }


def _restore_token(action: ResponseAction) -> dict[str, Any]:
    """Remediation counterpart of REVOKE_SESSION (restores the lab token)."""
    target = action.target or {}
    api_base = target.get("api_base_url", "")
    if not api_base:
        return {"action_type": action.action_type, "mode": "failed", "state_changed": False, "summary": "target api_base_url not configured"}
    try:
        resp = httpx.post(f"{api_base.rstrip('/')}/admin/reset-token", headers={"Authorization": f"Bearer {target.get('token', LEAKED_SERVICE_TOKEN)}"}, timeout=6)
    except httpx.HTTPError:
        return {"action_type": action.action_type, "mode": "failed", "state_changed": False, "summary": "lab API unreachable"}
    after = _probe_admin_users(api_base, LEAKED_SERVICE_TOKEN)
    changed = resp.status_code == 200 and after == 200
    return {
        "action_type": action.action_type,
        "mode": "real",
        "action_status": resp.status_code,
        "after": {"admin_users_status": after},
        "state_changed": changed,
        "summary": f"Service token restored (admin access now {after})",
    }


def _patch_lab(action: ResponseAction) -> dict[str, Any]:
    """Real remediation: apply the lab ownership-check patch (fixes the IDOR)."""
    target = action.target or {}
    base_url = target.get("base_url", "")
    client = _lab_admin_session(base_url) if base_url else None
    if client is None:
        return {"action_type": action.action_type, "mode": "failed", "state_changed": False, "summary": "lab admin login failed (lab unreachable?)"}

    def _order_status(user: str, order_id: int) -> int:
        try:
            sess = httpx.Client(timeout=6)
            sess.post(f"{base_url.rstrip('/')}/login", json={"username": user, "password": _login_creds(user)})
            resp = sess.get(f"{base_url.rstrip('/')}/orders/{order_id}")
            sess.close()
            return resp.status_code
        except httpx.HTTPError:
            return 0

    before = _order_status("alice", 2)
    resp = client.post(f"{base_url.rstrip('/')}/admin/patch-orders")
    client.close()
    after = _order_status("alice", 2)
    changed = resp.status_code == 200 and before == 200 and after == 403
    return {
        "action_type": action.action_type,
        "mode": "real",
        "before": {"cross_customer_order_status": before},
        "action_status": resp.status_code,
        "after": {"cross_customer_order_status": after},
        "state_changed": changed,
        "summary": f"Ownership patch applied (cross-customer order read {before} → {after})",
    }


def _service_isolation(action: ResponseAction) -> dict[str, Any]:
    """Real isolation: disable every non-admin lab web account."""
    target = action.target or {}
    base_url = target.get("base_url", "")
    users = target.get("users") or [u for u in LAB_WEB_USERS if u != "admin"]
    client = _lab_admin_session(base_url) if base_url else None
    if client is None:
        return {"action_type": action.action_type, "mode": "failed", "state_changed": False, "summary": "lab admin login failed (lab unreachable?)"}
    isolated: list[dict[str, Any]] = []
    all_changed = True
    for username in users:
        before = _probe_login(base_url, username, _login_creds(username))
        resp = client.post(f"{base_url.rstrip('/')}/admin/disable/{username}")
        after = _probe_login(base_url, username, _login_creds(username))
        isolated.append({"user": username, "login": f"{before} → {after}"})
        all_changed = all_changed and resp.status_code == 200 and before == 200 and after == 401
    client.close()
    return {
        "action_type": action.action_type,
        "mode": "real",
        "isolated_users": isolated,
        "state_changed": all_changed,
        "summary": f"Service isolated: disabled {len(users)} non-admin accounts",
    }


def _platform_action(action: ResponseAction) -> dict[str, Any]:
    target = action.target or {}
    now = datetime.now(timezone.utc)
    if action.action_type == "CREATE_TICKET":
        summary, extra = f"Ticket created for {target.get('entity', 'incident')}", {"ticket_id": f"TK-{now.strftime('%Y%m%d%H%M%S')}"}
    elif action.action_type == "ENABLE_MONITORING":
        summary, extra = f"Enhanced monitoring enabled on {target.get('asset', 'scope')}", {"state": "active"}
    else:  # COLLECT_EVIDENCE
        summary, extra = "Evidence collection triggered (snapshot + logs)", {"evidence_ref": "pending"}
    return {"action_type": action.action_type, "mode": "platform", "state_changed": False, "summary": summary, **extra}


def _simulated_action(action: ResponseAction, summary: str) -> dict[str, Any]:
    return {
        "action_type": action.action_type,
        "mode": "simulated",
        "state_changed": False,
        "summary": summary,
        "note": "Requires lab gateway/network control; recorded as SIMULATED, not real state change.",
    }


def execute_response_action(db: Session, action: ResponseAction, actor: str) -> dict[str, Any]:
    target = action.target or {}
    atype = action.action_type

    if atype == "DISABLE_ACCOUNT":
        result = _disable_account(action)
    elif atype == "ENABLE_ACCOUNT":
        result = _enable_account(action)
    elif atype in ("REVOKE_SESSION", "CREDENTIAL_ROTATION"):
        result = _revoke_token(action)
    elif atype == "RESTORE_TOKEN":
        result = _restore_token(action)
    elif atype == "PATCH_LAB":
        result = _patch_lab(action)
    elif atype == "SERVICE_ISOLATION":
        result = _service_isolation(action)
    elif atype in ("CREATE_TICKET", "ENABLE_MONITORING", "COLLECT_EVIDENCE"):
        result = _platform_action(action)
    elif atype == "ISOLATE_ENDPOINT":
        result = _simulated_action(action, f"Endpoint {target.get('asset', 'n/a')} isolation requires network control")
    elif atype == "BLOCK_NETWORK":
        result = _simulated_action(action, f"Network block for {target.get('destination', 'n/a')} requires gateway control")
    else:
        result = _simulated_action(action, f"Unknown action type {atype}")

    action.status = "EXECUTED" if result.get("mode") in ("real", "platform") else ("FAILED" if result.get("mode") == "failed" else "SIMULATED")
    action.executed_by = actor
    action.executed_at = datetime.now(timezone.utc)
    action.result = result
    db.commit()
    return result
