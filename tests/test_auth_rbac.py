"""Authentication, RBAC and tenant-isolation regression tests."""
from __future__ import annotations

from conftest import auth_headers, login

DEMO_PW = "SentinelX-2026!"


def test_login_success(client):
    resp = client.post("/api/auth/login", json={"email": "admin@acme.demo", "password": DEMO_PW})
    assert resp.status_code == 200
    body = resp.json()
    assert body["access_token"]
    assert body["refresh_token"]
    assert body["user"]["role"] == "ORG_ADMIN"


def test_login_wrong_password_denied(client):
    resp = client.post("/api/auth/login", json={"email": "admin@acme.demo", "password": "WrongPass-123"})
    assert resp.status_code == 401


def test_me_requires_token(client):
    resp = client.get("/api/auth/me")
    assert resp.status_code == 401


def test_refresh_flow(client):
    login_resp = login(client, "admin@acme.demo")
    refresh = login_resp["refresh_token"]
    resp = client.post("/api/auth/refresh", json={"refresh_token": refresh})
    assert resp.status_code == 200
    assert resp.json()["access_token"]


def test_logout_revokes_refresh(client):
    login_resp = login(client, "admin@acme.demo")
    refresh = login_resp["refresh_token"]
    headers = auth_headers(login_resp["access_token"])
    assert client.post("/api/auth/logout", headers=headers).status_code == 200
    resp = client.post("/api/auth/refresh", json={"refresh_token": refresh})
    assert resp.status_code == 401


def test_viewer_cannot_run_offensive(client):
    viewer = login(client, "viewer@acme.demo")
    headers = auth_headers(viewer["access_token"])
    # Viewer must not be able to create engagements (needs engagements:write)
    resp = client.post("/api/engagements", headers=headers, json={"name": "x", "scope_rules": []})
    assert resp.status_code == 403
    # ...or run scans
    resp = client.get("/api/jobs", headers=headers)
    assert resp.status_code == 403


def test_pentester_can_access_offensive(client):
    pentester = login(client, "pentester@acme.demo")
    headers = auth_headers(pentester["access_token"])
    resp = client.get("/api/engagements", headers=headers)
    assert resp.status_code == 200
    resp = client.get("/api/tools", headers=headers)
    assert resp.status_code == 200


def test_soc_cannot_approve_engagements(client):
    soc = login(client, "soc@acme.demo")
    headers = auth_headers(soc["access_token"])
    resp = client.post("/api/engagements", headers=headers, json={"name": "x"})
    assert resp.status_code == 403


# ---------- Tenant isolation ----------

def test_tenant_isolation_assets(client, acme, globex):
    """A user of org A must not read org B's assets."""
    acme_headers = auth_headers(acme["access_token"])
    globex_headers = auth_headers(globex["access_token"])

    acme_assets = client.get("/api/assets", headers=acme_headers).json()
    assert acme_assets, "acme should have assets"
    acme_asset_id = acme_assets[0]["id"]

    globex_assets = client.get("/api/assets", headers=globex_headers).json()
    assert globex_assets
    assert all(a["id"] != acme_asset_id for a in globex_assets)

    # Direct access attempt across tenants must fail
    resp = client.get(f"/api/assets/{acme_asset_id}", headers=globex_headers)
    assert resp.status_code == 404


def test_tenant_isolation_findings(client, acme, globex):
    acme_headers = auth_headers(acme["access_token"])
    globex_headers = auth_headers(globex["access_token"])
    acme_finding = client.get("/api/findings", headers=acme_headers).json()[0]
    resp = client.get(f"/api/findings/{acme_finding['id']}", headers=globex_headers)
    assert resp.status_code == 404


def test_tenant_isolation_evidence(client, acme, globex):
    acme_headers = auth_headers(acme["access_token"])
    globex_headers = auth_headers(globex["access_token"])
    ev = client.get("/api/evidence", headers=acme_headers).json()
    if not ev:
        return
    resp = client.get(f"/api/evidence/{ev[0]['id']}", headers=globex_headers)
    assert resp.status_code == 404
