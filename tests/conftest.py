"""Test fixtures.

Uses an isolated SQLite database per test session. Environment variables are
set BEFORE any sentinelx module import so the cached Settings pick them up.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

API_DIR = Path(__file__).resolve().parents[1] / "apps" / "api"
sys.path.insert(0, str(API_DIR))

_DB_PATH = API_DIR / "test_sentinelx.db"
os.environ["DATABASE_URL"] = f"sqlite:///{_DB_PATH.as_posix()}"
os.environ["ENVIRONMENT"] = "test"
os.environ["JWT_SECRET"] = "test-secret-not-for-production"
os.environ["ENCRYPTION_KEY"] = "test-encryption-key-not-for-production-0000000000"
os.environ["OBJECT_STORAGE_PATH"] = str((API_DIR / "storage" / "test-evidence").as_posix())

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from sentinelx.db import init_db  # noqa: E402
from sentinelx.main import app  # noqa: E402
from sentinelx.seed import seed_all  # noqa: E402


@pytest.fixture(scope="session", autouse=True)
def seeded():
    """Seed the isolated test database once, before every test in the session."""
    if _DB_PATH.exists():
        _DB_PATH.unlink()
    init_db()
    return seed_all()


@pytest.fixture(scope="session", autouse=True)
def _cleanup_db():
    yield
    from sentinelx.db import engine

    engine.dispose()
    if _DB_PATH.exists():
        try:
            _DB_PATH.unlink()
        except PermissionError:  # pragma: no cover - Windows lock
            pass


@pytest.fixture(autouse=True)
def _clean_login_attempts():
    """TestClient shares one client IP across the whole session; reset the
    per-IP login window before every test so rate-limit state never leaks
    between tests."""
    from sentinelx.db import SessionLocal
    from sentinelx.models import LoginAttempt

    with SessionLocal() as db:
        db.query(LoginAttempt).delete()
        db.commit()
    yield


@pytest.fixture()
def client():
    with TestClient(app) as c:
        yield c


def login(client: TestClient, email: str, password: str = "SentinelX-2026!") -> dict:
    resp = client.post("/api/auth/login", json={"email": email, "password": password})
    assert resp.status_code == 200, resp.text
    return resp.json()


@pytest.fixture()
def acme(seeded, client):
    data = login(client, "admin@acme.demo")
    data["org_id"] = next(iter(seeded))
    return data


@pytest.fixture()
def globex(seeded, client):
    data = login(client, "admin@globex.demo")
    org_ids = [k for k in seeded if seeded[k].get("org") == "globex"]
    data["org_id"] = org_ids[0]
    return data


def auth_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture()
def pentester(client):
    return login(client, "pentester@acme.demo")
