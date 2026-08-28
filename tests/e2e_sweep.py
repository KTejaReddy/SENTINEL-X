"""SENTINEL X — second E2E sweep (deeper corners).

Runs against a RUNNING server with a freshly seeded database. Extends
tests/e2e_live.py with:

  WebSocket realtime stream · job pause/resume/cancel/retry
  detection rule create/update (versioning) · all report types + export
  remediation → retest → verify · purple exercise completion
  evidence create · incident transitions · finding update
  tool availability reporting · AI copilot citations · deep tenancy
"""
from __future__ import annotations

import asyncio
import json
import sys
import time
import uuid

import httpx
import websockets

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000"
WS = BASE.replace("http://", "ws://") + "/ws/events"
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
        self.token = r.json()["access_token"]
        self.headers = {"Authorization": f"Bearer {self.token}"}

    def get(self, path: str, **kw):
        return self.c.get(path, headers=self.headers, **kw)

    def post(self, path: str, **kw):
        return self.c.post(path, headers=self.headers, **kw)

    def patch(self, path: str, **kw):
        return self.c.patch(path, headers=self.headers, **kw)


def wait_job(c: Client, job_id: str, timeout: float = 30.0) -> dict:
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        jobs = c.get("/api/jobs").json()
        job = next((j for j in jobs if j["id"] == job_id), None)
        if job:
            last = job["status"]
            if job["status"] in ("completed", "failed", "cancelled"):
                return job
        time.sleep(0.5)
    return {"status": "timeout", "last_seen": last}


def setup_engagement(c: Client, approver: Client | None = None) -> str:
    eng = c.post("/api/engagements", json={"name": f"Sweep ENG {uuid.uuid4().hex[:6]}", "target": "10.10.10.0/24"}).json()
    eng_id = eng["id"]
    c.post(f"/api/engagements/{eng_id}/scope", json={"kind": "INCLUDE", "value": "10.10.10.0/24"})
    c.post(f"/api/engagements/{eng_id}/submit")
    (approver or c).post(f"/api/engagements/{eng_id}/approve")
    c.post(f"/api/engagements/{eng_id}/start")
    return eng_id


async def ws_probe(c: Client) -> list[str]:
    """Connect to the realtime stream, trigger a job, and collect events."""
    events: list[str] = []
    async with websockets.connect(WS, open_timeout=10) as ws:
        await ws.send(json.dumps({"token": c.token}))
        # wait for the replay buffer (any event means auth + stream OK)
        try:
            msg = await asyncio.wait_for(ws.recv(), timeout=5)
            events.append(json.loads(msg)["type"])
        except asyncio.TimeoutError:
            pass
        approver = Client("admin@acme.demo")
        eng_id = setup_engagement(c, approver)
        job = c.post("/api/jobs", json={"kind": "scan", "tool": "lab-range", "engagement_id": eng_id, "target_ref": "10.10.10.11", "params": {"scenario": "web_app_authorization"}}).json()
        job_id = job["id"]
        deadline = time.time() + 10
        while time.time() < deadline:
            try:
                msg = await asyncio.wait_for(ws.recv(), timeout=3)
                events.append(json.loads(msg)["type"])
            except asyncio.TimeoutError:
                break
        wait_job(c, job_id)
        # disconnect by exiting the context
    return events


def main() -> None:
    print(f"\n=== SENTINEL X sweep #2 against {BASE} ===\n")

    admin = Client("admin@acme.demo")
    pen = Client("pentester@acme.demo")
    soc = Client("soc@acme.demo")

    # ---------- 1. Realtime WebSocket ----------
    print("[realtime WebSocket]")
    ws_events = asyncio.run(ws_probe(pen))
    check("WS connects + auth accepted", any(e for e in ws_events), str(ws_events)[:120])
    check("WS streams job lifecycle events", any(e in ws_events for e in ("job_queued", "job_started", "job_completed")), str(ws_events)[:160])
    check("WS streams detection/ingest events", any(e in ws_events for e in ("event_ingested", "detection_hit")), str(ws_events)[:160])

    # ---------- 2. Job lifecycle controls ----------
    print("[job lifecycle controls]")
    eng_id = setup_engagement(pen, admin)
    j1 = pen.post("/api/jobs", json={"kind": "scan", "tool": "lab-range", "engagement_id": eng_id, "target_ref": "10.10.10.11", "params": {"scenario": "web_app_authorization"}}).json()["id"]
    paused = pen.post(f"/api/jobs/{j1}/pause")
    check("pause queued job", paused.status_code == 200 and paused.json().get("status") == "paused", paused.text[:100])
    resumed = pen.post(f"/api/jobs/{j1}/resume")
    check("resume paused job", resumed.status_code == 200 and resumed.json().get("status") == "queued", resumed.text[:100])
    done = wait_job(pen, j1)
    err1 = done.get("error") or ""
    check("job completes after resume", done.get("status") == "completed", f"status={done.get('status')} last_seen={done.get('last_seen')} err={err1[:80]}")
    j2 = pen.post("/api/jobs", json={"kind": "scan", "tool": "lab-range", "engagement_id": eng_id, "target_ref": "10.10.10.12", "params": {"scenario": "api_authorization"}}).json()["id"]
    pen.post(f"/api/jobs/{j2}/pause")
    cancelled = pen.post(f"/api/jobs/{j2}/cancel")
    check("cancel paused job", cancelled.status_code == 200 and cancelled.json().get("status") == "cancelled", cancelled.text[:100])
    # retry a failed job (out-of-scope target → policy denial)
    bad_eng = setup_engagement(pen, admin)
    j3 = pen.post("/api/jobs", json={"kind": "scan", "tool": "lab-range", "engagement_id": bad_eng, "target_ref": "198.51.100.7"}).json()["id"]
    bad = wait_job(pen, j3)
    berr = bad.get("error") or ""
    check("out-of-scope job fails cleanly", bad.get("status") == "failed", f"{bad.get('status')} {berr[:80]}")
    check("failure recorded as structured error", "Policy denied" in berr, berr[:120])
    retried = pen.post(f"/api/jobs/{j3}/retry")
    check("retry re-queues failed job", retried.status_code == 200 and retried.json().get("status") == "queued", retried.text[:100])
    pen.post(f"/api/jobs/{j3}/cancel")

    # ---------- 3. Detection rule management ----------
    print("[detection rules]")
    engineer = Client("engineer@acme.demo")
    rule = engineer.post("/api/detections/rules", json={
        "rule_id": f"E2E-{uuid.uuid4().hex[:6]}", "name": "Sweep Lateral Movement", "description": "internal connection after auth",
        "source": "sigma", "severity": "high", "status": "DRAFT", "logic": {"match": "network:internal_connection"},
        "mitre": ["T1021"],
    })
    check("create detection rule", rule.status_code == 200, rule.text[:150])
    rid = rule.json()["id"]
    v1 = rule.json()["version"]
    updated = engineer.patch(f"/api/detections/rules/{rid}", json={"status": "DEPLOYED"})
    check("deploy rule bumps version", updated.status_code == 200 and updated.json()["version"] == v1 + 1, updated.text[:120])
    check("rule deployed", updated.json().get("status") == "DEPLOYED")

    # ---------- 4. All report types ----------
    print("[report types]")
    for rtype in ("executive", "pentest", "purple", "incident", "remediation"):
        gen = pen.post("/api/reports/generate", json={"report_type": rtype, "title": f"Sweep {rtype} report"})
        ok = gen.status_code == 200
        check(f"generate {rtype} report", ok, gen.text[:130])
        if ok and gen.json().get("id"):
            exp = admin.get(f"/api/reports/{gen.json()['id']}/export", params={"fmt": "markdown"})
            check(f"export {rtype} report", exp.status_code == 200 and len(exp.content) > 100, exp.text[:100])

    # ---------- 5. Remediation -> retest -> verify ----------
    print("[remediation -> retest -> verify]")
    finding = next(f for f in pen.get("/api/findings").json() if f.get("status") in ("NEW", "TRIAGED", "VALIDATED"))
    rem = admin.post("/api/remediation", json={"finding_id": finding["id"], "notes": "Sweep remediation", "due_date": "2026-12-31"})
    check("create remediation", rem.status_code == 200, rem.text[:150])
    rem_id = rem.json().get("id") or rem.json().get("remediation", {}).get("id")
    verified = admin.post(f"/api/remediation/{rem_id}/verify", json={})
    check("verify remediation triggers retest", verified.status_code == 200, verified.text[:150])
    retests = admin.get("/api/retests").json()
    latest = retests[0] if retests else {}
    check("retest recorded for finding", latest.get("finding_id") == finding["id"] or latest.get("status"), str(latest)[:120])

    # ---------- 6. Purple exercise completion ----------
    print("[purple completion]")
    ciso = Client("ciso@acme.demo")
    pe = ciso.post("/api/purple/exercise", json={"scenario": "web_app_authorization", "engagement_id": eng_id})

    check("purple exercise enqueued", pe.status_code == 200 and pe.json().get("exercise_id"), pe.text[:150])
    pj = wait_job(ciso, pe.json().get("exercise_id"), timeout=30)
    pjerr = pj.get("error") or ""
    check("purple job completes", pj.get("status") == "completed", f"status={pj.get('status')} last_seen={pj.get('last_seen')} err={pjerr[:80]}")
    cov = admin.get("/api/purple/coverage").json()
    check("coverage summary after exercise", isinstance(cov, dict) and cov.get("purple_exercises", 0) >= 1, str(cov)[:100])

    # ---------- 7. Evidence create ----------
    print("[evidence]")
    ev = pen.post("/api/evidence", json={"finding_id": finding["id"], "kind": "SCREENSHOT", "data": {"label": "Sweep evidence", "note": "captured during controlled test"}, "tool": "lab-range"})
    check("create evidence entry", ev.status_code == 200, ev.text[:150])
    if ev.status_code == 200:
        evd = pen.get(f"/api/evidence/{ev.json()['id']}")
        check("evidence retrievable with hash", evd.status_code == 200 and evd.json().get("content_hash"), str(evd.json())[:120])

    # ---------- 8. Incident transitions + finding update ----------
    print("[state transitions]")
    inc0 = soc.get("/api/incidents").json()[0]
    for status in ("INVESTIGATING", "CONTAINED", "ERADICATION", "RESOLVED", "CLOSED"):
        r = soc.patch(f"/api/incidents/{inc0['id']}", json={"status": status})
        if r.status_code != 200:
            check(f"incident → {status}", False, r.text[:100])
            break
    else:
        check("incident lifecycle OPEN->CLOSED", True)
    fd = pen.patch(f"/api/findings/{finding['id']}", json={"status": "FIXED"})
    check("finding status update", fd.status_code == 200 and fd.json().get("status") == "FIXED", fd.text[:100])

    # ---------- 9. Tool availability ----------
    print("[tool availability]")
    tools = pen.get("/api/tools").json()
    lab = next((t for t in tools if t.get("name") == "lab-range"), None)
    check("lab-range reported installed", lab and lab.get("installed") is True, str(lab)[:120])
    nmap = next((t for t in tools if t.get("name") == "nmap"), None)
    check("missing tools reported NOT INSTALLED (graceful)", nmap is not None and nmap.get("installed") is False, str(nmap)[:120])

    # ---------- 10. AI copilot citations ----------
    print("[AI copilot citations]")
    cp = pen.post("/api/ai/copilot", json={"question": "Show incidents related to the most critical finding"})
    check("copilot answers", cp.status_code == 200 and cp.json().get("answer"), cp.text[:150])
    check("copilot cites internal references", cp.status_code == 200 and len(cp.json().get("citations", [])) >= 1, str(cp.json().get("citations"))[:120])

    # ---------- 11. Deep tenancy ----------
    print("[deep tenancy]")
    globex = Client("admin@globex.demo")
    acme_eng = admin.get("/api/engagements").json()[0]
    leak = globex.get(f"/api/engagements/{acme_eng['id']}")
    check("cross-tenant engagement read rejected (404)", leak.status_code == 404, str(leak.status_code))
    acme_inc = soc.get("/api/incidents").json()[0]
    leak2 = globex.get(f"/api/incidents/{acme_inc['id']}")
    check("cross-tenant incident read rejected (404)", leak2.status_code == 404, str(leak2.status_code))
    cross_job = globex.post("/api/jobs", json={"kind": "scan", "tool": "lab-range", "engagement_id": eng_id, "target_ref": "10.10.10.11"})
    check("cross-tenant job creation rejected (403/404)", cross_job.status_code in (403, 404), str(cross_job.status_code))

    # ---------- 12. Audit shows the sweep ----------
    print("[audit coverage]")
    audit = admin.get("/api/audit").json()
    actions = {a.get("action") for a in audit}
    for expected in ("job.create", "job.cancel", "rule.create", "rule.update", "report.generate", "purple.exercise.run", "incident.update", "finding.update", "evidence.create"):
        check(f"audit records {expected}", expected in actions)

    print(f"\n=== RESULT: {PASS} passed, {FAIL} failed ===")
    if FAILURES:
        print("Failures:")
        for f in FAILURES:
            print(f"  - {f}")
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    main()
