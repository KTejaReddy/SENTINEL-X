"""LAB ONLY — intentionally vulnerable web application.

Flaws (documented for the lab, do NOT mirror in real code):
  1. Broken authentication — hardcoded shared credentials, no session expiry.
  2. Broken object-level authorization (IDOR) — /orders/<id> returns any order
     without checking ownership.
  3. Broken function-level authorization — /admin is reachable by any
     authenticated user regardless of role.

This container exists exclusively inside the isolated cyber range.

The app also emits structured JSONL telemetry (auth events, admin access,
order access) so SENTINEL X's defensive pipeline can observe real lab
activity, and exposes /admin/disable|enable endpoints used by real response
actions to change actual application state.
"""
import json
import logging
import os
import time
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path

from flask import Flask, jsonify, request, session

app = Flask(__name__)
app.secret_key = "lab-only-insecure-secret"  # documented lab weakness

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

LOG_PATH = Path(os.environ.get("LAB_EVENT_LOG", Path(__file__).resolve().parents[2] / "logs" / "lab-web.jsonl"))
LOG_PATH.parent.mkdir(parents=True, exist_ok=True)

ORDERS = {
    1: {"id": 1, "customer": "alice", "product": "Laptop", "amount": 1299, "card_tail": "4242"},
    2: {"id": 2, "customer": "bob", "product": "Monitor", "amount": 349, "card_tail": "1111"},
    3: {"id": 3, "customer": "carol", "product": "Server Rack", "amount": 8999, "card_tail": "0001"},
    4: {"id": 4, "customer": "dave", "product": "GPU", "amount": 1599, "card_tail": "7777"},
    5: {"id": 5, "customer": "erin", "product": "NAS", "amount": 599, "card_tail": "3333"},
    6: {"id": 6, "customer": "frank", "product": "Switch", "amount": 129, "card_tail": "9999"},
}

USERS = {"alice": "alice", "admin": "admin"}  # shared weak credentials (documented)
DISABLED_USERS: set[str] = set()  # real, mutable app state for response actions
ORDER_AUTH_PATCHED: bool = False  # real, mutable remediation state (fixes FLAW 2)


def emit(event_type: str, severity: str, user: str | None, message: str, meta: dict | None = None) -> None:
    """Write a normalized telemetry line the SENTINEL X watcher ingests."""
    line = json.dumps(
        {
            "ts": datetime.now(timezone.utc).isoformat(),
            "source": "lab-web",
            "event_type": event_type,
            "severity": severity,
            "user": user,
            "asset": "lab-web",
            "message": message,
            "meta": meta or {},
        }
    )
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(line + "\n")


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("user"):
            return jsonify({"error": "authentication required"}), 401
        return f(*args, **kwargs)

    return wrapper


@app.get("/")
def index():
    return jsonify({"service": "lab-shop-web", "routes": ["/login", "/orders/<id>", "/admin"]})


@app.post("/login")
def login():
    data = request.get_json(silent=True) or {}
    user = data.get("username", "")
    password = data.get("password", "")
    if user in USERS and USERS[user] == password and user not in DISABLED_USERS:
        session["user"] = user
        emit("authentication:login_success", "info", user, f"login ok for {user}")
        return jsonify({"ok": True, "user": user})
    emit("authentication:login_attempt", "medium", user or "unknown", f"failed login for {user}", {"password_tried": bool(password)})
    return jsonify({"error": "invalid credentials or account disabled"}), 401


@app.get("/orders/<int:order_id>")
@login_required
def get_order(order_id):
    # FLAW 2: no ownership check — any authenticated user can read any order.
    # After the remediation patch (ORDER_AUTH_PATCHED) a server-side ownership
    # check is enforced — the lab's real state changes and the retest reflects it.
    order = ORDERS.get(order_id)
    if order is None:
        return jsonify({"error": "not found"}), 404
    if ORDER_AUTH_PATCHED and session.get("user") != order["customer"] and session.get("user") != "admin":
        emit("authorization:denied", "medium", session.get("user"), f"cross-customer order {order_id} denied (patched)", {"order_id": order_id, "owner": order["customer"]})
        return jsonify({"error": "forbidden"}), 403
    emit("web:api_request", "medium", session.get("user"), f"order {order_id} viewed", {"order_id": order_id, "customer": order["customer"]})
    return jsonify(order)


@app.get("/admin")
@login_required
def admin():
    # FLAW 3: any authenticated user (e.g. alice) can reach the admin panel.
    who = session.get("user")
    if who and who != "admin":
        emit("authentication:privilege_boundary", "high", who, "non-admin user reached admin panel", {"route": "/admin"})
    return jsonify(
        {
            "panel": "admin",
            "users": list(USERS.keys()),
            "disabled": sorted(DISABLED_USERS),
            "note": "this endpoint must require an ADMIN role",
        }
    )


@app.post("/admin/disable/<username>")
@login_required
def admin_disable(username):
    """Real state change: disables a user account (used by response actions)."""
    if username not in USERS:
        return jsonify({"error": "unknown user"}), 404
    DISABLED_USERS.add(username)
    emit("admin:user_disabled", "info", session.get("user"), f"account {username} disabled", {"disabled": username})
    return jsonify({"ok": True, "disabled": sorted(DISABLED_USERS)})


@app.post("/admin/enable/<username>")
@login_required
def admin_enable(username):
    """Real state change: re-enables a user account (used by remediation)."""
    DISABLED_USERS.discard(username)
    emit("admin:user_enabled", "info", session.get("user"), f"account {username} enabled", {"enabled": username})
    return jsonify({"ok": True, "disabled": sorted(DISABLED_USERS)})


@app.post("/admin/patch-orders")
@login_required
def admin_patch_orders():
    """Real remediation state change: enforce server-side ownership on /orders."""
    global ORDER_AUTH_PATCHED
    ORDER_AUTH_PATCHED = True
    emit("remediation:order_auth_patched", "info", session.get("user"), "ownership check enforced on /orders")
    return jsonify({"ok": True, "order_auth_patched": ORDER_AUTH_PATCHED})


@app.post("/admin/unpatch-orders")
@login_required
def admin_unpatch_orders():
    """Real state change: revert the ownership patch (re-introduce FLAW 2)."""
    global ORDER_AUTH_PATCHED
    ORDER_AUTH_PATCHED = False
    emit("remediation:order_auth_unpatched", "info", session.get("user"), "ownership check removed on /orders")
    return jsonify({"ok": True, "order_auth_patched": ORDER_AUTH_PATCHED})


@app.get("/healthz")
def healthz():
    return jsonify({"status": "ok", "disabled": sorted(DISABLED_USERS)})


if __name__ == "__main__":
    time.sleep(1)  # let db warm up in compose
    app.run(host="0.0.0.0", port=int(os.environ.get("LAB_WEB_PORT", "5000")), debug=False)
