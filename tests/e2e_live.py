"""SENTINEL X — live end-to-end test.

Drives the complete product lifecycle against a RUNNING server
(scripts/dev.sh) with the seeded demo database.

Usage:
    python tests/e2e_live.py [base_url]

Covered:
  auth + refresh + logout revocation · command center · assets · attack surface
  engagement lifecycle (create→scope→submit→approve→start→check-scope)
  job execution (lab-range) · finding creation + authorized validation · evidence
  controlled security exercise (full pipeline) · attack paths + graph
  event ingest · detection · incidents + AI analysis · timeline
  response actions (approve → execute) · threat hunt · purple team
  remediation · retests · reports · AI triage / copilot / action gating
  audit log · system status · RBAC denial · tenant isolation
"""
from __future__ import annotations

import sys
import time
import uuid

import httpx

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000"
PASSWORD = "SentinelX-2026!"

PASS = 0
FAIL = 0
FAILURES: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"  PASS  {name}")
    else:
        FAIL += 1
        FAILURES.append(name)
        print(f"  FAIL  {name}  {detail}")


class Client:
    def __init__(self, email: str, password: str = PASSWORD):
        self.c = httpx.Client(base_url=BASE, timeout=30)
        r = self.c.post("/api/auth/login", json={"email": email, "password": password})
        assert r.status_code == 200, f"login {email}: {r.status_code} {r.text}"
        data = r.json()
        self.token = data["access_token"]
        self.refresh = data["refresh_token"]
        self.headers = {"Authorization": f"Bearer {self.token}"}

    def get(self, path: str, **kw):
        return self.c.get(path, headers=self.headers, **kw)

    def post(self, path: str, **kw):
        return self.c.post(path, headers=self.headers, **kw)

    def patch(self, path: str, **kw):
        return self.c.patch(path, headers=self.headers, **kw)


def wait_job(c: Client, job_id: str, timeout: float = 25.0) -> dict:
    deadline = time.time() + timeout
    last_seen = None
    while time.time() < deadline:
        jobs = c.get("/api/jobs").json()
        job = next((j for j in jobs if j["id"] == job_id), None)
        if job:
            last_seen = job["status"]
            if job["status"] in ("completed", "failed", "cancelled"):
                return job
        time.sleep(0.5)
    return {"status": "timeout", "last_seen": last_seen, "job_id": job_id}


def main() -> None:
    print(f"\n=== SENTINEL X live E2E against {BASE} ===\n")

    # ---------- 1. Auth ----------
    print("[auth]")
    admin = Client("admin@acme.demo")
    check("login + access token", bool(admin.token))
    me = admin.get("/api/auth/me").json()
    check("auth/me returns user", me.get("email") == "admin@acme.demo", str(me)[:80])
    tmp = Client("admin@acme.demo")
    ref = tmp.post("/api/auth/refresh", json={"refresh_token": tmp.refresh})
    check("refresh token rotates", ref.status_code == 200 and ref.json().get("access_token"))
    tmp.post("/api/auth/logout", json={"refresh_token": tmp.refresh})
    revoked = tmp.post("/api/auth/refresh", json={"refresh_token": tmp.refresh})
    check("logout revokes refresh family", revoked.status_code in (401, 400), f"{revoked.status_code} {revoked.text[:80]}")

    # ---------- 2. Command center ----------
    print("[command center]")
    dash = admin.get("/api/command-center/data")
    check("command-center/data 200", dash.status_code == 200, dash.text[:120])
    d = dash.json()
    posture = d.get("posture", {})
    check("posture has risk + attack paths",
          posture.get("overall_risk") is not None and posture.get("active_attack_paths") is not None, str(posture)[:160])
    check("live incidents feed", isinstance(d.get("live_incidents"), list) and len(d["live_incidents"]) >= 1)
    check("live events feed", isinstance(d.get("live_events"), list))
    check("critical findings present", len(d.get("critical_findings", [])) >= 1)
    check("top attack paths present", isinstance(d.get("top_attack_paths"), list) and len(d["top_attack_paths"]) >= 1)

    # ---------- 3. Assets + attack surface ----------
    print("[assets + attack surface]")
    assets = admin.get("/api/assets").json()
    check("assets seeded (>=20)", len(assets) >= 20, f"got {len(assets)}")
    surf = admin.get("/api/attack-surface").json()
    check("attack-surface has totals", surf.get("total_assets") == len(assets), str(surf)[:120])
    ast = admin.get(f"/api/assets/{assets[0]['id']}").json()
    check("asset detail", ast.get("id") == assets[0]["id"])
    services = admin.get(f"/api/assets/{assets[0]['id']}/services")
    check("asset services", services.status_code == 200)
    lab_web = next(a for a in assets if a.get("name") == "lab-web")
    check("lab-web asset in scope of lab CIDR", (lab_web.get("ip_address") or "").startswith("10.10.10."), str(lab_web)[:120])

    # ---------- 4. Engagement lifecycle (pentester drives offensive) ----------
    print("[engagement lifecycle]")
    pen = Client("pentester@acme.demo")
    eng = pen.post(
        "/api/engagements",
        json={"name": "E2E Controlled Assessment", "description": "live e2e", "target": "10.10.10.0/24"},
    ).json()
    check("engagement created (DRAFT)", eng.get("status") == "DRAFT", str(eng)[:100])
    eng_id = eng["id"]
    pen.post(f"/api/engagements/{eng_id}/scope", json={"kind": "INCLUDE", "value": "10.10.10.0/24"})
    scoped = pen.post(f"/api/engagements/{eng_id}/scope", json={"kind": "EXCLUDE", "value": "10.10.10.50"})
    check("scope rules added", len(scoped.json().get("scope_rules", [])) >= 2, scoped.text[:120])
    before = pen.post(f"/api/engagements/{eng_id}/check-scope", json={"target": "10.10.10.11"})
    check("scope engine blocks DRAFT engagement", before.json().get("allowed") is False, before.text[:100])
    pen.post(f"/api/engagements/{eng_id}/submit")
    approved = admin.post(f"/api/engagements/{eng_id}/approve")
    check("ORG_ADMIN approves engagement", approved.status_code == 200 and approved.json().get("status") == "APPROVED", approved.text[:100])
    start = pen.post(f"/api/engagements/{eng_id}/start")
    check("engagement started", start.json().get("status") == "RUNNING", start.text[:100])
    scope_ok = pen.post(f"/api/engagements/{eng_id}/check-scope", json={"target": "10.10.10.11"})
    check("in-scope target allowed", scope_ok.json().get("allowed") is True, scope_ok.text[:100])
    scope_deny = pen.post(f"/api/engagements/{eng_id}/check-scope", json={"target": "10.10.10.50"})
    check("exclude rule blocks target", scope_deny.json().get("allowed") is False, scope_deny.text[:100])
    scope_out = pen.post(f"/api/engagements/{eng_id}/check-scope", json={"target": "203.0.113.9"})
    check("out-of-scope target rejected", scope_out.json().get("allowed") is False)

    # ---------- 5. Jobs ----------
    print("[jobs]")
    job = pen.post("/api/jobs", json={"kind": "scan", "tool": "lab-range", "engagement_id": eng_id, "target_ref": "10.10.10.11", "params": {"scenario": "web_app_authorization"}})
    check("job created", job.status_code == 200, job.text[:150])
    job_id = job.json().get("id")
    done = wait_job(pen, job_id)
    err = done.get("error") or ""
    check("job completed by worker", done.get("status") == "completed", f"{done.get('status')} {err[:120]}")
    check("job result is structured", isinstance(done.get("result"), dict) and len(done.get("result", {})) > 0, str(done.get("result"))[:100])
    tools = pen.get("/api/tools").json()
    check("tool registry lists lab-range", any(t.get("name") == "lab-range" for t in tools), str(tools)[:120])
    hc = pen.post("/api/tools/health-check")
    check("tools/health-check 200", hc.status_code == 200)

    # ---------- 6. Findings + validation + evidence ----------
    print("[findings + validation + evidence]")
    findings = pen.get("/api/findings").json()
    check("findings seeded", len(findings) >= 5, f"got {len(findings)}")
    created = pen.post("/api/findings", json={
        "title": "E2E Broken Object-Level Authorization",
        "engagement_id": eng_id, "severity": "HIGH", "cvss": 8.1, "cwe": "CWE-639",
        "category": "Authorization", "endpoint": "10.10.10.11",
        "description": "IDOR on /orders/{id} (E2E)",
        "remediation": "Enforce object-level authorization server-side",
    })
    check("finding created with engagement", created.status_code == 200, created.text[:150])
    fid = created.json()["id"]
    val = pen.post(f"/api/findings/{fid}/validate", json={})
    check("authorized validation enqueued", val.status_code == 200 and val.json().get("status") == "VALIDATING", val.text[:150])
    vuls = pen.get("/api/vulnerabilities").json()
    check("vulnerabilities view", isinstance(vuls, list) and len(vuls) >= 1)
    ev = pen.get("/api/evidence").json()
    check("evidence vault has entries", isinstance(ev, list) and len(ev) >= 1, f"got {len(ev)}")
    if ev:
        evd = pen.get(f"/api/evidence/{ev[0]['id']}")
        check("evidence detail", evd.status_code == 200)

    # ---------- 7. Controlled security exercise (full loop) ----------
    print("[controlled exercise]")
    ex = admin.post("/api/ai/exercise", json={"scenario": "api_authorization"})
    check("exercise creates engagement+job", ex.status_code == 200, ex.text[:150])
    exj = ex.json().get("jobs", [{}])[0]
    exdone = wait_job(admin, exj.get("job_id"), timeout=30)
    err = exdone.get("error") or ""
    check("exercise job completes", exdone.get("status") == "completed", f"status={exdone.get('status')} last_seen={exdone.get('last_seen')} job_id={exdone.get('job_id')} err={err[:120]}")

    # ---------- 8. Attack paths + graph ----------
    print("[attack paths]")
    paths = pen.get("/api/attack-paths").json()
    check("attack paths computed", len(paths) >= 1, f"got {len(paths)}")
    recomputed = pen.post("/api/attack-paths/compute").json()
    check("attack-paths/compute", isinstance(recomputed, list) and len(recomputed) >= 1)
    graph = pen.get("/api/attack-graph").json()
    check("attack graph has nodes+edges", len(graph.get("nodes", [])) >= 3 and len(graph.get("edges", [])) >= 1, str(graph)[:100])

    # ---------- 9. Defensive: events, detection, incidents ----------
    print("[defensive]")
    soc = Client("soc@acme.demo")
    ing = soc.post("/api/events", json={"event_id": uuid.uuid4().hex, "timestamp": "2026-08-13T00:00:00Z", "source": "e2e-test", "event_type": "network:port_scan", "severity": "low", "metadata": {"note": "live e2e event"}})
    check("event ingest", ing.status_code == 200, ing.text[:120])
    feed = soc.get("/api/events/feed").json()
    check("event feed has data", isinstance(feed, list) and len(feed) >= 1, f"got {len(feed)}")
    rules = soc.get("/api/detections/rules").json()
    check("detection rules seeded", len(rules) >= 1, f"got {len(rules)}")
    inc = soc.get("/api/incidents").json()
    check("incidents seeded", len(inc) >= 1, f"got {len(inc)}")
    inc0 = inc[0]
    tl = soc.get(f"/api/incidents/{inc0['id']}/timeline")
    check("incident timeline", tl.status_code == 200 and len(tl.json()) >= 1, tl.text[:120])
    analysis = soc.post(f"/api/incidents/{inc0['id']}/analyze")
    check("AI incident analysis", analysis.status_code == 200, analysis.text[:150])
    an = analysis.json()
    check("analysis separates fact/inference/hypothesis",
          all(k in an for k in ("facts", "inferences", "hypotheses", "recommendations")), str(an)[:150])
    linked = soc.post(f"/api/incidents/{inc0['id']}/link-finding", json={"finding_id": fid})
    check("link finding to incident", linked.status_code == 200, linked.text[:120])

    # ---------- 10. Response playbooks (approve → execute) ----------
    print("[response playbooks]")
    pbs = soc.get("/api/playbooks").json()
    check("playbooks seeded", len(pbs) >= 1, f"got {len(pbs)}")
    action = soc.post(f"/api/playbooks/{pbs[0]['id']}/actions", json={
        "name": "E2E isolate endpoint", "action_type": "ISOLATE_ENDPOINT", "risk_level": "HIGH",
        "target": {"asset": lab_web.get("name"), "entity": "lab-web"}, "incident_id": inc0["id"],
    })
    check("HIGH action requires approval", action.status_code == 200 and action.json().get("status") == "PENDING_APPROVAL", action.text[:150])
    act_id = action.json()["id"]
    denied = soc.post(f"/api/responses/actions/{act_id}/approve", json={"approve": True})
    check("SOC cannot self-approve HIGH action", denied.status_code == 403, denied.text[:100])
    approved = admin.post(f"/api/responses/actions/{act_id}/approve", json={"approve": True, "note": "e2e approval"})
    check("ORG_ADMIN approves action", approved.status_code == 200 and approved.json().get("status") == "APPROVED", approved.text[:120])
    executed = soc.post(f"/api/responses/actions/{act_id}/execute")
    # ISOLATE_ENDPOINT requires network control not present here — the adapter
    # must report SIMULATED honestly, never a fake "EXECUTED" containment.
    executed_body = executed.json()
    check(
        "execute action via adapter (honest mode)",
        executed.status_code == 200 and executed_body.get("status") == "SIMULATED" and executed_body.get("result", {}).get("mode") == "simulated",
        executed.text[:200],
    )
    inc_after = soc.get(f"/api/incidents/{inc0['id']}").json()
    check(
        "simulated action does NOT falsely contain incident",
        inc_after.get("status") != "CONTAINED",
        f"incident must not be marked contained by a simulated action: {inc_after.get('status')}",
    )

    # ---------- 11. Threat hunting ----------
    print("[threat hunting]")
    hunt = soc.post("/api/hunts", json={"query": "suspicious authentication patterns"})
    check("hunt translates to query plan", hunt.status_code == 200 and hunt.json().get("ok") is True, hunt.text[:150])
    bad = soc.post("/api/hunts", json={"query": "SELECT * FROM users; DROP TABLE"})
    check("hunt rejects free-form queries", bad.status_code == 200 and bad.json().get("ok") is False, bad.text[:100])

    # ---------- 12. Purple team ----------
    print("[purple team]")
    cov = admin.get("/api/purple/coverage").json()
    check("purple coverage summary", isinstance(cov, dict) and "detection_rules_deployed" in cov, str(cov)[:120])
    res = admin.get("/api/purple/results").json()
    check("purple results", isinstance(res, list))
    ciso = Client("ciso@acme.demo")
    pv = ciso.post("/api/purple/exercise", json={"scenario": "web_app_authorization", "engagement_id": eng_id})
    check("purple exercise runs", pv.status_code == 200, pv.text[:150])

    # ---------- 13. Remediation + retest ----------
    print("[remediation + retest]")
    rem = admin.get("/api/remediation").json()
    check("remediation list", isinstance(rem, list))
    retests = admin.get("/api/retests").json()
    check("retests list", isinstance(retests, list))

    # ---------- 14. Reports ----------
    print("[reports]")
    gen = pen.post("/api/reports/generate", json={"report_type": "executive", "title": "E2E Executive Report"})
    check("report generated", gen.status_code == 200, gen.text[:150])
    report_id = gen.json().get("id")
    if report_id:
        exp = admin.get(f"/api/reports/{report_id}/export", params={"fmt": "markdown"})
        check("report export", exp.status_code == 200 and len(exp.content) > 100, exp.text[:100])
    reps = admin.get("/api/reports").json()
    check("reports list", isinstance(reps, list) and len(reps) >= 1)

    # ---------- 15. AI ----------
    print("[AI]")
    triage = pen.post("/api/ai/triage", json={"finding_id": fid})
    check("AI triage typed output", triage.status_code == 200, triage.text[:150])
    tr = triage.json()
    check("triage has classification+confidence", tr.get("classification") and 0 <= tr.get("confidence", 0) <= 1)
    cp = pen.post("/api/ai/copilot", json={"question": "Which vulnerabilities participate in a path to the database?"})
    check("copilot answers from retrieval", cp.status_code == 200 and cp.json().get("answer"), cp.text[:150])
    action_req = pen.post("/api/ai/action", json={"action": "create_validation_job", "target_id": lab_web["id"], "objective": "authorization_boundary_check"})
    check("AI action request gated", action_req.status_code == 200, action_req.text[:150])
    bad_action = pen.post("/api/ai/action", json={"action": "delete_production", "target_id": lab_web["id"], "objective": "nope"})
    check("AI unsupported action rejected", bad_action.status_code == 200 and bad_action.json().get("allowed") is False, bad_action.text[:150])

    # ---------- 16. Admin / audit / system ----------
    print("[admin + audit + system]")
    audit = admin.get("/api/audit")
    check("audit log", audit.status_code == 200 and len(audit.json()) >= 1, audit.text[:120])
    notifs = admin.get("/api/notifications").json()
    check("notifications", isinstance(notifs, list))
    st = admin.get("/api/system/status").json()
    comps = st.get("components", {})
    check("system status components", comps.get("api", {}).get("health") == "OK" and comps.get("database", {}).get("health") == "OK", str(st)[:160])
    mt = admin.get("/api/system/metrics")
    check("system metrics", mt.status_code == 200)
    search = admin.get("/api/search", params={"q": "lab-db"})
    check("global search", search.status_code == 200 and len(search.json().get("results", search.json())) >= 1, search.text[:120])

    # ---------- 17. RBAC ----------
    print("[RBAC]")
    viewer = Client("viewer@acme.demo")
    denied = viewer.post("/api/jobs", json={"kind": "scan", "tool": "lab-range", "engagement_id": eng_id, "target_ref": "10.10.10.11"})
    check("viewer cannot run jobs (403)", denied.status_code == 403, denied.text[:120])
    ro = viewer.get("/api/assets")
    check("viewer can read assets", ro.status_code == 200)
    can_audit = viewer.get("/api/audit")
    check("viewer cannot read audit log (403)", can_audit.status_code == 403, str(can_audit.status_code))

    # ---------- 18. Tenant isolation ----------
    print("[tenant isolation]")
    globex = Client("admin@globex.demo")
    g_assets = globex.get("/api/assets").json()
    g_ids = {a["id"] for a in g_assets}
    a_ids = {a["id"] for a in assets}
    check("globex sees its own assets", len(g_assets) >= 20)
    check("no cross-tenant asset leak", not (a_ids & g_ids))
    leak = globex.get(f"/api/assets/{assets[0]['id']}")
    check("cross-tenant read rejected (404)", leak.status_code == 404, str(leak.status_code))
    g_dash = globex.get("/api/command-center/data")
    check("globex dashboard isolated (200)", g_dash.status_code == 200)

    # ---------- Summary ----------
    print(f"\n=== RESULT: {PASS} passed, {FAIL} failed ===")
    if FAILURES:
        print("Failures:")
        for f in FAILURES:
            print(f"  - {f}")
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    main()
