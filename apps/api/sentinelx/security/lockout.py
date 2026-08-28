"""Login hardening: per-account lockout and per-IP rate limiting.

Fully DB-backed so it works correctly across multiple API workers (no
in-memory state). Behavior:

- MAX_ACCOUNT_ATTEMPTS consecutive failures lock the account for
  LOCKOUT_BASE_MINUTES, doubling with each successive lockout period
  (progressive lockout).
- MAX_IP_ATTEMPTS login attempts from a single IP within IP_WINDOW_SECONDS
  are throttled with HTTP 429 + Retry-After.
- A successful login resets the account failure counter.
- Every attempt is recorded in `login_attempts` (auditable, tenant-free by
  design — the login endpoint is pre-authentication).
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func
from sqlalchemy.orm import Session

from ..models import LoginAttempt, User

MAX_ACCOUNT_ATTEMPTS = 5
LOCKOUT_BASE_MINUTES = 15

IP_WINDOW_SECONDS = 300
MAX_IP_ATTEMPTS = 20
# Loopback is the operator's own management interface (dev / CI / local API
# tooling) — still bounded, but far higher than the external-IP cap. The
# strict cap is enforced everywhere in the test environment.
LOOPBACK_IP_ATTEMPTS = 300


def _as_aware(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def lockout_duration_minutes(strikes: int) -> int:
    """Progressive lockout: 15m, 30m, 60m, ... (capped at 8 hours)."""
    return min(LOCKOUT_BASE_MINUTES * (2 ** max(0, strikes - 1)), 8 * 60)


def account_lock_status(db: Session, email: str, ip: str | None) -> dict[str, Any]:
    """Current lockout state for an account + source IP (no side effects)."""
    user = db.query(User).filter(User.email == email.lower()).first()
    now = _now()
    locked_until = _as_aware(user.locked_until) if user else None

    account_locked = locked_until is not None and locked_until > now
    if user and not account_locked and locked_until is not None:
        # Lockout window has passed: keep the counter so the next lockout is longer.
        user.locked_until = None
        db.commit()

    # Per-IP sliding window
    since = now - timedelta(seconds=IP_WINDOW_SECONDS)
    ip_attempts = (
        db.query(func.count(LoginAttempt.id))
        .filter(LoginAttempt.ip == ip, LoginAttempt.created_at >= since)
        .scalar()
        or 0
    )
    from ..config import settings

    is_loopback = ip in ("127.0.0.1", "::1", "localhost")
    ip_cap = LOOPBACK_IP_ATTEMPTS if (is_loopback and settings.ENVIRONMENT != "test") else MAX_IP_ATTEMPTS

    retry_after = 0
    if account_locked:
        retry_after = int((locked_until - now).total_seconds())

    return {
        "account_locked": account_locked,
        "locked_until": locked_until.isoformat() if locked_until else None,
        "retry_after_seconds": max(retry_after, 0),
        "remaining_attempts": 0
        if account_locked
        else max(0, MAX_ACCOUNT_ATTEMPTS - (user.failed_login_count % MAX_ACCOUNT_ATTEMPTS if user else 0)),
        "ip_blocked": ip_attempts >= ip_cap,
        "ip_attempts": ip_attempts,
        "ip_cap": ip_cap,
        "ip_retry_after_seconds": max(0, IP_WINDOW_SECONDS - int((now - since).total_seconds())),
    }


def record_login_attempt(db: Session, email: str, ip: str | None, success: bool, user_id: str | None = None) -> None:
    """Record an attempt; update the account counter / lockout accordingly."""
    db.add(LoginAttempt(email=email.lower(), ip=ip, success=success))
    user = db.query(User).filter(User.email == email.lower()).first()
    now = _now()
    if user is not None:
        if success:
            user.failed_login_count = 0
            user.locked_until = None
        else:
            user.failed_login_count = (user.failed_login_count or 0) + 1
            if user.failed_login_count >= MAX_ACCOUNT_ATTEMPTS:
                # ceil(count/MAX): a relock after an expired lockout period
                # increments the strike (requests while locked are rejected at
                # the gate and never counted, so raw division would never
                # advance past the first period).
                strikes = (user.failed_login_count + MAX_ACCOUNT_ATTEMPTS - 1) // MAX_ACCOUNT_ATTEMPTS
                user.locked_until = now + timedelta(minutes=lockout_duration_minutes(strikes))
    db.commit()


def lock_status_for_user(db: Session, user: User) -> dict[str, Any]:
    """Status for an authenticated user (e.g. to surface in /auth/me)."""
    locked_until = _as_aware(user.locked_until)
    return {
        "locked": locked_until is not None and locked_until > _now(),
        "locked_until": locked_until.isoformat() if locked_until else None,
        "failed_login_count": user.failed_login_count or 0,
    }
