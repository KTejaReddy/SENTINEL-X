"""Master acceptance test — the complete SENTINEL X security lifecycle.

Drives the entire product against the LIVE lab targets with REAL operations:

  engagement → scope → real DAST scan → real findings → validation → evidence
  → attack path → controlled attack → live telemetry → detection → incident
  → AI analysis → approved response → REAL state change (verified by probes)
  → remediation → real retest (PASS) → regression check (FAIL) → report

Requires the API and the lab targets to be running (see scripts/dev.sh and
cyber-range). Skips cleanly when they are not — this is the CI lab job's
primary test (ci.yml / lab.yml).
"""
from __future__ import annotations

import os
import time
from datetime import datetime, timezone

import pytest
import requests

API = os.environ.get("API_URL", "http://127.0.0.1:8000/api")
LAB_WEB = os.environ.get("LAB_WEB_URL", "http://127.0.0.1:5000")
LAB_API = os.environ.get("LAB_API_URL", "http://127.0.0.1:9002")

ADMIN = ("admin@acme.demo", "SentinelX-2026!")
PENTESTER = ("pentester@acme.demo", "SentinelX-2026!")
SOC = ("soc@acme.demo", "SentinelX-2026!")


def _api_unreachable() -> bool:
    try:
        return requests.get(f"{API}/health", timeout=2).status_code != 200
    except requests.RequestException:
        return True


def _lab_unreachable() -> bool:
    try:
        return requests.get(f"{LAB_WEB}/healthz", timeout=2).status_code != 200 or requests.get(f"{LAB_API}/healthz", timeout=2).status_code != 200
    except requests.RequestException:
        return True


pytestmark = pytest.mark.skipif(_api_unreachable() or _lab_unreachable(), reason="API and/or lab targets not reachable — start them (scripts/dev.sh + cyber-range) before running the lifecycle test")


class Api:
    def __init__(self, email: str, password: str):
        self.base = API
        resp = requests.post(f"{self.base}/auth/login", json={"email": email, "password": password}, timeout=10)
        # Be tolerant of transient rate-limit pressure during rapid local runs.
        for _ in range(60):
            if resp.status_code == 429:
                time.sleep(2)
                resp = requests.post(f"{self.base}/auth/login", json={"email": email, "password": password}, timeout=10)
                continue
            break
        assert resp.status_code == 200, f"login {email} failed: {resp.text}"
        self.token = resp.json()["access_token"]
        self.user = resp.json()["user"]

    def headers(self) -> dict:
        return {"Authorization": f"Bearer {self.token}"}

    def req(self, method: str, path: str, **kw) -> requests.Response:
        kw.setdefault("timeout", 30)
        kw.setdefault("headers", self.headers())
        return requests.request(method, f"{self.base}{path}", **kw)

    def get(self, path: str, **kw) -> dict:
        r = self.req("GET", path, **kw)
        assert r.status_code == 200, f"GET {path}: {r.status_code} {r.text[:300]}"
        return r.json()

    def post(self, path: str, json=None, expect: int = 200) -> requests.Response:
        r = self.req("POST", path, json=json or {})
        assert r.status_code == expect, f"POST {path}: {r.status_code} {r.text[:300]}"
        return r


def wait_until(fn, timeout: float = 30, interval: float = 1.5, desc: str = ""):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            last = fn()
            if last:
                return last
        except AssertionError:
            pass
        time.sleep(interval)
    raise AssertionError(f"timed out waiting for: {desc or 'condition'} (last={last!r})")


def wait_job(api: Api, job_id: str, timeout: float = 90) -> dict:
    def done():
        jobs = api.get("/jobs")
        job = next((j for j in jobs if j["id"] == job_id), None)
        assert job is not None, f"job {job_id} not found"
        assert job["status"] in ("completed", "failed", "cancelled"), f"job {job_id} still {job['status']}"
        return job

    job = wait_until(done, timeout=timeout, interval=2.0, desc=f"job {job_id} terminal")
    assert job["status"] == "completed", f"job {job_id} failed: {job.get('error')} result={job.get('result')}"
    return job


def lab_reset() -> None:
    """Restore the lab to a known-good state (real HTTP)."""
    s = requests.Session()
    s.post(f"{LAB_WEB}/login", json={"username": "admin", "password": "admin"}, timeout=5)
    s.post(f"{LAB_WEB}/admin/enable/alice", timeout=5)
    s.post(f"{LAB_WEB}/admin/unpatch-orders", timeout=5)
    requests.post(f"{LAB_API}/admin/reset-token", headers={"Authorization": "Bearer lab-service-token-2026"}, timeout=5)


# ---------------------------------------------------------------------------

def test_complete_security_lifecycle():
    lab_reset()
    t0 = datetime.now(timezone.utc).isoformat()

    pentester = Api(*PENTESTER)
    admin = Api(*ADMIN)
    soc = Api(*SOC)

    # ---- 1. Engagement: authorize the lab targets ----
    eng = pentester.post(
        "/engagements",
        json={
            "name": f"Lifecycle {time.strftime('%H%M%S')}",
            "description": "Complete lifecycle acceptance test",
            "config": {"allowed_tools": ["dast", "lab-range"], "max_request_rate": 50, "destructive_testing": False},
            "scope_rules": [
                {"kind": "INCLUDE", "match_type": "CIDR", "value": "10.10.10.0/24", "note": "lab range"},
                {"kind": "EXCLUDE", "match_type": "CIDR", "value": "10.10.10.13/32", "note": "db out of testing scope"},
            ],
        },
    ).json()
    eng_id = eng["id"]
    assert eng["status"] == "DRAFT"

    pentester.post(f"/engagements/{eng_id}/submit")
    admin.post(f"/engagements/{eng_id}/approve")
    admin.post(f"/engagements/{eng_id}/start")
    assert admin.get(f"/engagements/{eng_id}")["status"] == "RUNNING"

    # ---- 2. Real DAST scan against the lab ----
    assets = admin.get("/assets?size=200")
    lab_web = next(a for a in assets if a["name"] == "lab-web")
    lab_api = next(a for a in assets if a["name"] == "lab-api")

    scan_job = pentester.post(
        "/jobs",
        json={
            "engagement_id": eng_id,
            "kind": "scan",
            "tool": "dast",
            "target_ref": lab_web["id"],
            "params": {"base_url": LAB_WEB, "api_base_url": LAB_API, "probe_set": "full"},
        },
    ).json()
    job = wait_job(pentester, scan_job["id"])
    # Re-runs dedupe against existing findings (created=0, updated=8), so the
    # real evidence is created OR refreshed — either way probes ran for real.
    meta = job["result"].get("meta", {})
    assert meta.get("probes_executed", 0) >= 5, f"expected real probes, got {job['result']}"
    assert meta.get("target_unreachable") is False, "scan reported target unreachable — probes did not run"
    assert job["result"]["findings_created"] + job["result"]["findings_updated"] >= 5, f"expected >=5 findings, got {job['result']}"

    # ---- 3. Findings created from REAL responses ----
    findings = admin.get("/findings?size=200")
    scan_findings = [f for f in findings if f["source"] == "dast"]
    by_title = {f["title"]: f for f in scan_findings}
    assert any("IDOR" in t for t in by_title), [f["title"] for f in scan_findings]
    assert any("BOLA" in t for t in by_title), [f["title"] for f in scan_findings]
    assert any("Leaked service token" in t for t in by_title), [f["title"] for f in scan_findings]
    idor = next(f for f in scan_findings if "IDOR" in f["title"])
    # Findings must be asset-linked (feeds attack paths)
    assert idor["asset_id"], "DAST finding was not linked to an asset"
    # The finding's engagement must be active for validate/retest
    idor_eng = admin.get(f"/engagements/{idor['engagement_id']}")
    assert idor_eng["status"] in ("APPROVED", "RUNNING"), f"finding's engagement not active: {idor_eng['status']}"

    # ---- 4. Authorized validation → evidence ----
    pentester.post(f"/findings/{idor['id']}/validate")
    wait_until(lambda: admin.get(f"/findings/{idor['id']}")["status"] == "VALIDATED", timeout=60, desc="finding VALIDATED")
    evidence = admin.get("/evidence")
    assert any(e["finding_id"] == idor["id"] for e in evidence), "no evidence attached to validated finding"

    # ---- 5. Attack paths from real state ----
    paths = admin.post("/attack-paths/compute").json()
    assert paths, "no attack paths computed"
    assert any(p["status"] == "ACTIVE" for p in paths)
    assert admin.get(f"/findings/{idor['id']}")["attack_path_relevant"], "IDOR finding should participate in an attack path"

    # ---- 6. Controlled attack (real HTTP) → live telemetry ----
    s = requests.Session()
    assert s.post(f"{LAB_WEB}/login", json={"username": "alice", "password": "alice"}, timeout=5).status_code == 200
    assert s.get(f"{LAB_WEB}/admin", timeout=5).status_code == 200          # privilege boundary
    assert requests.get(f"{LAB_API}/orders/5", headers={"X-User": "alice"}, timeout=5).status_code == 200  # BOLA
    assert requests.get(f"{LAB_API}/admin/users", headers={"Authorization": "Bearer lab-service-token-2026"}, timeout=5).status_code == 200

    def telemetry_arrived():
        events = admin.get("/events?size=200")
        live = [e for e in events if e.get("source") == "lab-app" and e["event_type"] in ("authentication:privilege_boundary", "data:sensitive_access")]
        if not live:
            return None
        assert all(e["demo"] is False for e in live)
        return live

    live = wait_until(telemetry_arrived, timeout=30, desc="live telemetry ingested")
    assert any(e["event_type"] == "authentication:privilege_boundary" for e in live)
    assert any(e["event_type"] == "data:sensitive_access" for e in live)

    # ---- 7. Detection → incident from real telemetry ----
    def incident_arrived():
        incidents = admin.get("/incidents")
        # Detection may create a fresh incident OR re-fire into an existing
        # open one for the same rule (merge). Either way the rule must have
        # matched real telemetry after t0.
        new = [
            i for i in incidents
            if not i.get("demo") and i["detection_sources"]
            and (i["created_at"] >= t0 or (i.get("updated_at") or "") >= t0)
        ]
        if not new:
            return None
        return new

    new_incidents = wait_until(incident_arrived, timeout=30, desc="detection incident from live telemetry")
    inc = next(i for i in new_incidents if any(r in i["detection_sources"] for r in ("SIG-001", "SIG-002")))
    inc_id = inc["id"]

    # ---- 8. AI incident analysis ----
    analysis = admin.post(f"/incidents/{inc_id}/analyze").json()
    assert analysis.get("facts") and analysis.get("inferences"), f"analysis incomplete: {analysis}"
    assert analysis.get("summary") and analysis.get("confidence") is not None, f"analysis incomplete: {analysis}"

    # ---- 9. Response: approval workflow + REAL state change ----
    playbooks = admin.get("/playbooks")
    assert playbooks, "no playbooks exist"
    pb_id = playbooks[0]["id"]

    action = admin.post(f"/playbooks/{pb_id}/actions", json={
        "incident_id": inc_id, "name": "Disable compromised lab account", "risk_level": "HIGH",
        "action_type": "DISABLE_ACCOUNT", "target": {"base_url": LAB_WEB, "username": "alice"}, "requires_approval": True,
    })
    action_id = action.json()["id"]
    assert action.json()["status"] == "PENDING_APPROVAL"

    # SOC cannot approve HIGH-risk actions (RBAC)
    assert soc.post(f"/responses/actions/{action_id}/approve", json={"approve": True, "note": "soc self-approve"}, expect=403).status_code == 403
    admin.post(f"/responses/actions/{action_id}/approve", json={"approve": True, "note": "admin approved"})

    exec_resp = admin.post(f"/responses/actions/{action_id}/execute").json()
    result = exec_resp["result"]
    assert result["mode"] == "real", f"expected real mode: {result}"
    assert result["state_changed"] is True, f"expected measured state change: {result}"

    # Incident only contained after measured real change
    assert admin.get(f"/incidents/{inc_id}")["status"] == "CONTAINED"

    # Direct verification: alice can no longer log in (real before/after)
    assert requests.post(f"{LAB_WEB}/login", json={"username": "alice", "password": "alice"}, timeout=5).status_code == 401

    # ---- 10. Remediation: re-enable + patch the flaw (real state change) ----
    rem_action = admin.post(
        f"/playbooks/{pb_id}/actions",
        json={"incident_id": inc_id, "name": "Re-enable account", "risk_level": "LOW",
              "action_type": "ENABLE_ACCOUNT", "target": {"base_url": LAB_WEB, "username": "alice"}, "requires_approval": False},
    ).json()
    admin.post(f"/responses/actions/{rem_action['id']}/execute")
    assert requests.post(f"{LAB_WEB}/login", json={"username": "alice", "password": "alice"}, timeout=5).status_code == 200

    patch_action = admin.post(
        f"/playbooks/{pb_id}/actions",
        json={"incident_id": inc_id, "name": "Apply ownership patch", "risk_level": "MEDIUM",
              "action_type": "PATCH_LAB", "target": {"base_url": LAB_WEB}, "requires_approval": False},
    ).json()
    admin.post(f"/responses/actions/{patch_action['id']}/execute")
    # Direct verification: cross-customer read now denied
    s2 = requests.Session()
    s2.post(f"{LAB_WEB}/login", json={"username": "alice", "password": "alice"}, timeout=5)
    assert s2.get(f"{LAB_WEB}/orders/2", timeout=5).status_code == 403

    # ---- 11. Real retest: PASS (vulnerability actually fixed) ----
    retest_job = pentester.post(
        f"/findings/{idor['id']}/retest",
        json={"tool": "dast", "base_url": LAB_WEB, "api_base_url": LAB_API, "probe_set": "full"},
    ).json()
    wait_job(pentester, retest_job["id"], timeout=90)
    assert admin.get(f"/findings/{idor['id']}")["status"] == "VERIFIED", "finding should be VERIFIED after passing retest"
    retests = admin.get("/retests")
    passed = [r for r in retests if r["finding_id"] == idor["id"] and r["status"] == "PASSED"]
    assert passed, f"expected PASSED retest for {idor['id']}: {retests}"

    # ---- 12. Regression check: reintroduce the flaw → retest FAILS ----
    s3 = requests.Session()
    s3.post(f"{LAB_WEB}/login", json={"username": "admin", "password": "admin"}, timeout=5)
    s3.post(f"{LAB_WEB}/admin/unpatch-orders", timeout=5)
    reg_job = pentester.post(
        f"/findings/{idor['id']}/retest",
        json={"tool": "dast", "base_url": LAB_WEB, "api_base_url": LAB_API, "probe_set": "full"},
    ).json()
    wait_job(pentester, reg_job["id"], timeout=90)
    reg_finding = admin.get(f"/findings/{idor['id']}")
    assert reg_finding["status"] == "VALIDATING", f"expected regression -> VALIDATING: {reg_finding['status']}"
    assert reg_finding.get("metadata_json", {}).get("regression") is True, "regression flag missing"

    # ---- 13. Report reflects the real lifecycle ----
    report = admin.post("/reports/generate", json={"report_type": "pentest", "engagement_id": eng_id, "title": "Lifecycle report"}).json()
    assert report["id"]
    export_resp = admin.req("GET", f"/reports/{report['id']}/export?fmt=markdown")
    assert export_resp.status_code == 200, export_resp.text[:300]
    exported = export_resp.text
    assert "IDOR" in exported or "Insecure Direct Object" in exported, "report missing the DAST finding"
    assert "Retest" in exported or "retest" in exported, "report missing retest data"

    # ---- 14. Copilot answers from the real lifecycle data ----
    copilot = admin.post("/ai/copilot", json={"question": "which vulnerabilities participate in a path to the database?"}).json()
    assert copilot.get("answer"), "copilot returned no answer"
    assert copilot.get("citations"), "copilot returned no citations"

    # Restore lab state for repeatability
    lab_reset()
    print(f"\n[LIFECYCLE OK] engagement={eng_id} finding={idor['id']} incident={inc_id} action={action_id}")
