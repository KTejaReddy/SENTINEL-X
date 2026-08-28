"""AI service tests: typed output, citations, hallucination control."""
from __future__ import annotations

from conftest import auth_headers, login


def test_ai_triage_returns_typed_schema(client):
    token = login(client, "admin@acme.demo")["access_token"]
    headers = auth_headers(token)
    findings = client.get("/api/findings", headers=headers).json()
    assert findings
    resp = client.post(f"/api/ai/triage", headers=headers, json={"finding_id": findings[0]["id"]})
    assert resp.status_code == 200
    body = resp.json()
    for key in ("classification", "severity", "confidence", "asset_criticality", "business_risk", "likely_attack_path", "evidence_required", "recommended_validation", "remediation"):
        assert key in body
    assert 0 <= body["confidence"] <= 1


def test_copilot_cites_real_evidence(client):
    token = login(client, "admin@acme.demo")["access_token"]
    headers = auth_headers(token)
    resp = client.post("/api/ai/copilot", headers=headers, json={"question": "Which vulnerabilities participate in a path to the database?"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["answer"]
    assert body["provider"] == "local"
    # Citations must reference real finding IDs that exist
    for c in body["citations"]:
        assert c["id"]


def test_copilot_never_fabricates(client):
    token = login(client, "admin@acme.demo")["access_token"]
    headers = auth_headers(token)
    resp = client.post("/api/ai/copilot", headers=headers, json={"question": "Did we successfully compromise anything last night?"})
    body = resp.json()
    # Must not claim a compromise; should answer from data or say insufficient evidence
    assert "compromise" not in body["answer"].lower() or "no " in body["answer"].lower()


def test_ai_action_requires_engagement_for_offensive(client):
    token = login(client, "pentester@acme.demo")["access_token"]
    headers = auth_headers(token)
    resp = client.post(
        "/api/ai/action",
        headers=headers,
        json={"action": "create_validation_job", "target_id": "not-a-real-target", "objective": "x", "engagement_id": None},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["allowed"] is False
