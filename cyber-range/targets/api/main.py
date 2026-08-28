"""LAB ONLY — intentionally vulnerable API.

Flaws (documented for the lab, do NOT mirror in real code):
  1. Broken object-level authorization (BOLA) — /orders/{id} returns any
     order; authorization is checked against a header any client can set.
  2. Broken function-level authorization (BFLA) — /admin/users is callable
     by any caller with a valid (leaked) service token.
  3. No rate limiting on /api/search.

This container exists exclusively inside the isolated cyber range.

The API emits structured JSONL telemetry (BOLA accesses, token usage) and
exposes /admin/revoke-token|reset-token used by real response actions to
rotate the leaked service token — an actual, measurable state change.
"""
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException

app = FastAPI(title="lab-shop-api")

LOG_PATH = Path(os.environ.get("LAB_API_EVENT_LOG", Path(__file__).resolve().parents[2] / "logs" / "lab-api.jsonl"))
LOG_PATH.parent.mkdir(parents=True, exist_ok=True)

ORDERS = {
    1: {"id": 1, "customer": "alice", "product": "Laptop", "amount": 1299},
    2: {"id": 2, "customer": "bob", "product": "Monitor", "amount": 349},
    3: {"id": 3, "customer": "carol", "product": "Server Rack", "amount": 8999},
    4: {"id": 4, "customer": "dave", "product": "GPU", "amount": 1599},
    5: {"id": 5, "customer": "erin", "product": "NAS", "amount": 599},
}

# Documented lab weakness: shared token printed in the web app source.
LEAKED_SERVICE_TOKEN = os.environ.get("LAB_SERVICE_TOKEN", "lab-service-token-2026")
CURRENT_TOKEN = LEAKED_SERVICE_TOKEN  # mutable: rotated by real response actions


def emit(event_type: str, severity: str, user: str | None, message: str, meta: dict | None = None) -> None:
    line = json.dumps(
        {
            "ts": datetime.now(timezone.utc).isoformat(),
            "source": "lab-api",
            "event_type": event_type,
            "severity": severity,
            "user": user,
            "asset": "lab-api",
            "message": message,
            "meta": meta or {},
        }
    )
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(line + "\n")


@app.get("/")
def root():
    return {"service": "lab-shop-api", "routes": ["/orders/{id}", "/admin/users", "/search"]}


@app.get("/orders/{order_id}")
def get_order(order_id: int, x_user: str = Header(default="anonymous")):
    # FLAW 1: trusts a client-supplied header for identity — no server-side
    # ownership check. Any x-user can read any order.
    order = ORDERS.get(order_id)
    if order is None:
        raise HTTPException(status_code=404, detail="not found")
    if x_user != order["customer"]:
        # BOLA: caller accessed another customer's order
        emit("data:sensitive_access", "critical", x_user, f"cross-customer order {order_id} accessed", {"order_id": order_id, "owner": order["customer"], "accessing_as": x_user})
    else:
        emit("web:api_request", "medium", x_user, f"order {order_id} accessed by owner", {"order_id": order_id})
    return {**order, "accessed_as": x_user}


@app.get("/admin/users")
def admin_users(authorization: str = Header(default="")):
    # FLAW 2: the "service token" is hardcoded and leaked in the web app
    # source — possession of it grants admin without a role check.
    if authorization != f"Bearer {CURRENT_TOKEN}":
        raise HTTPException(status_code=401, detail="unauthorized")
    emit("authentication:privilege_boundary", "high", "service", "admin API used with leaked service token", {"route": "/admin/users"})
    return {"users": ["alice", "bob", "carol", "dave", "erin", "admin"]}


@app.post("/admin/revoke-token")
def revoke_token(authorization: str = Header(default="")):
    """Real state change: rotate the leaked service token (response action)."""
    global CURRENT_TOKEN
    if authorization != f"Bearer {CURRENT_TOKEN}":
        raise HTTPException(status_code=401, detail="unauthorized")
    old = CURRENT_TOKEN
    CURRENT_TOKEN = "rotated-" + old + "-" + os.urandom(4).hex()
    emit("response:token_revoked", "info", "service", "service token rotated", {"old_prefix": old[:12]})
    return {"ok": True, "token_rotated": True, "old_token_invalid": True}


@app.post("/admin/reset-token")
def reset_token(authorization: str = Header(default="")):
    """Real state change: restore the original leaked token (remediation/retest)."""
    global CURRENT_TOKEN
    if authorization != f"Bearer {CURRENT_TOKEN}":
        raise HTTPException(status_code=401, detail="unauthorized")
    CURRENT_TOKEN = LEAKED_SERVICE_TOKEN
    emit("response:token_reset", "info", "service", "service token restored")
    return {"ok": True, "token_reset": True}


@app.get("/search")
def search(q: str = ""):
    # FLAW 3: unauthenticated, unthrottled search endpoint.
    return {"query": q, "hits": []}


@app.get("/healthz")
def healthz():
    return {"status": "ok"}
