"""Login hardening tests: progressive account lockout + per-IP rate limiting.

Each test uses its own dedicated user so lockout state never leaks into the
shared seeded accounts used by the rest of the suite.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest

from sentinelx.models import LoginAttempt, User
from sentinelx.security.lockout import (
    LOCKOUT_BASE_MINUTES,
    MAX_ACCOUNT_ATTEMPTS,
    MAX_IP_ATTEMPTS,
)

DEMO_PW = "SentinelX-2026!"
PW = "valid-password-2026"


def _aware(dt):
    """SQLite drops tzinfo — normalize to aware UTC."""
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _db():
    from sentinelx.db import SessionLocal

    return SessionLocal()


def _make_user(email: str) -> None:
    from sentinelx.models import Organization
    from sentinelx.security.auth import hash_password

    with _db() as db:
        org = db.query(Organization).first()
        db.add(
            User(
                org_id=org.id, email=email, name="hardening-probe",
                password_hash=hash_password(PW), role="VIEWER", status="ACTIVE",
            )
        )
        db.commit()


def _fail_login(client, email: str, n: int = 1):
    for _ in range(n):
        resp = client.post("/api/auth/login", json={"email": email, "password": "wrong-password"})
        assert resp.status_code in (401, 429)


@pytest.fixture()
def victim(client):
    email = f"lock-victim-{uuid.uuid4().hex[:8]}@acme.demo"
    _make_user(email)
    return email


def test_account_locks_after_max_failures(client, victim):
    _fail_login(client, victim, n=MAX_ACCOUNT_ATTEMPTS)

    # Even the correct password is now rejected with 429 while locked
    resp = client.post("/api/auth/login", json={"email": victim, "password": PW})
    assert resp.status_code == 429
    assert resp.json()["detail"]["retry_after_seconds"] > 0
    assert int(resp.headers.get("Retry-After", "0")) > 0

    with _db() as db:
        user = db.query(User).filter(User.email == victim).first()
        assert user.failed_login_count >= MAX_ACCOUNT_ATTEMPTS
        assert user.locked_until is not None
        assert _aware(user.locked_until) > datetime.now(timezone.utc)


def test_lockout_expires_then_login_resets(client, victim):
    _fail_login(client, victim, n=MAX_ACCOUNT_ATTEMPTS)

    # Force-expire the lockout to simulate the window passing
    with _db() as db:
        user = db.query(User).filter(User.email == victim).first()
        user.locked_until = datetime.now(timezone.utc) - timedelta(seconds=1)
        db.commit()

    resp = client.post("/api/auth/login", json={"email": victim, "password": PW})
    assert resp.status_code == 200

    with _db() as db:
        user = db.query(User).filter(User.email == victim).first()
        assert user.failed_login_count == 0
        assert user.locked_until is None


def test_progressive_lockout_doubles(client, victim):
    _fail_login(client, victim, n=MAX_ACCOUNT_ATTEMPTS)
    with _db() as db:
        user = db.query(User).filter(User.email == victim).first()
        first = _aware(user.locked_until)
        assert user.failed_login_count == MAX_ACCOUNT_ATTEMPTS
        assert first > datetime.now(timezone.utc)

    # Force-expire and fail again: next lockout must be longer (progressive)
    with _db() as db:
        user = db.query(User).filter(User.email == victim).first()
        user.locked_until = datetime.now(timezone.utc) - timedelta(seconds=1)
        db.commit()
    _fail_login(client, victim, n=MAX_ACCOUNT_ATTEMPTS)

    with _db() as db:
        user = db.query(User).filter(User.email == victim).first()
        # 5 failures from period 1 + 1 post-expiry failure (the rest are
        # rejected while re-locked) — the relock must be the 30-minute tier.
        assert user.failed_login_count == MAX_ACCOUNT_ATTEMPTS + 1
        second = _aware(user.locked_until)
        # 30-minute lockout ends ~15 minutes after the 15-minute one began
        assert second - first >= timedelta(minutes=LOCKOUT_BASE_MINUTES) - timedelta(seconds=5)


def test_ip_rate_limit(client):
    # Unknown accounts avoid interfering with account lockout state.
    for i in range(MAX_IP_ATTEMPTS):
        resp = client.post("/api/auth/login", json={"email": f"nobody{i}@acme.demo", "password": "wrong-password"})
        assert resp.status_code == 401
    # The next attempt from this IP is blocked by the per-IP window
    resp = client.post("/api/auth/login", json={"email": "admin@acme.demo", "password": DEMO_PW})
    assert resp.status_code == 429
    assert "Too many login attempts" in resp.json()["detail"]["message"]


def test_attempts_are_audited(client, victim):
    _fail_login(client, victim, n=2)
    with _db() as db:
        rows = (
            db.query(LoginAttempt)
            .filter(LoginAttempt.email == victim, LoginAttempt.success.is_(False))
            .order_by(LoginAttempt.created_at.desc())
            .limit(2)
            .all()
        )
        assert len(rows) == 2
        assert rows[0].ip is not None
