"""Controlled Cyber-Range adapter.

Replays the *expected behavior* of the intentionally-vulnerable lab targets
(cyber-range, CIDR 10.10.10.0/24) through the real pipeline. Everything it
produces is explicitly labeled CONTROLLED LAB / DEMO DATA and is never
presented as live production telemetry.

Hard constraints:
- Refuses any target outside LAB_CIDR / lab assets.
- Never claims exploitation — output is labeled "controlled lab replay".
- Scope + policy engines still gate every run.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy.orm import Session

from ..base import (
    AdapterError,
    NormalizedEvent,
    NormalizedFinding,
    ToolAdapter,
)
from ...config import settings

LAB_LABEL = "CONTROLLED LAB"
DEMO_LABEL = "DEMO DATA"

SCENARIOS: dict[str, dict[str, Any]] = {
    "web_app_authorization": {
        "title": "Public Web Application — Broken Object-Level Authorization",
        "mitre": ["T1190", "T1078", "T1213"],
        "stages": [
            {"stage": "Recon", "technique": "T1595", "events": [("network:port_scan", "low")]},
            {"stage": "Initial Access", "technique": "T1190", "events": [("authentication:login_attempt", "medium")]},
            {"stage": "Execution", "technique": "T1059", "events": [("web:api_request", "medium")]},
            {"stage": "Privilege", "technique": "T1548", "events": [("authentication:privilege_boundary", "high")]},
            {"stage": "Lateral Movement", "technique": "T1021", "events": [("network:internal_connection", "high")]},
            {"stage": "Collection", "technique": "T1005", "events": [("data:sensitive_access", "critical")]},
        ],
        "findings": [
            {
                "title": "Broken Object-Level Authorization in /api/orders/{id}",
                "severity": "HIGH",
                "cwe": "CWE-639",
                "category": "Authorization",
                "endpoint": "https://lab-web.lab.local/api/orders/1042",
                "cvss": 8.1,
                "description": (
                    "The endpoint returns another customer's order when the numeric identifier is "
                    "incremented; no ownership check is performed. (Controlled lab replay.)"
                ),
                "remediation": "Enforce object-level authorization on the server using the authenticated principal.",
                "confidence": 0.95,
                "evidence": {
                    "type": "lab_replay",
                    "method": "GET",
                    "url": "https://lab-web.lab.local/api/orders/1042",
                    "auth": "session cookie (lab user alice)",
                    "response_status": 200,
                    "response_note": "Returned resource owned by another lab user",
                },
            },
            {
                "title": "Weak Session Cookie Entropy",
                "severity": "MEDIUM",
                "cwe": "CWE-330",
                "category": "Session Management",
                "endpoint": "https://lab-web.lab.local/",
                "cvss": 5.3,
                "description": "Session tokens are predictable. (Controlled lab replay.)",
                "remediation": "Use a CSPRNG for session tokens.",
                "confidence": 0.9,
                "evidence": {"type": "lab_replay", "note": "session token entropy sampled", "entropy_bits": 48},
            },
        ],
    },
    "api_authorization": {
        "title": "API Authorization Weakness",
        "mitre": ["T1190", "T1078", "T1213"],
        "stages": [
            {"stage": "Recon", "technique": "T1595", "events": [("network:port_scan", "low")]},
            {"stage": "Initial Access", "technique": "T1078", "events": [("authentication:api_token_use", "low")]},
            {"stage": "Execution", "technique": "T1059", "events": [("web:api_request", "medium")]},
            {"stage": "Privilege", "technique": "T1548", "events": [("api:function_level_authorization", "high")]},
            {"stage": "Collection", "technique": "T1005", "events": [("data:sensitive_access", "high")]},
        ],
        "findings": [
            {
                "title": "Broken Function-Level Authorization on Admin API",
                "severity": "CRITICAL",
                "cwe": "CWE-862",
                "category": "Authorization",
                "endpoint": "https://lab-api.lab.local/v1/admin/users",
                "cvss": 9.1,
                "description": "Non-admin API keys can invoke admin endpoints. (Controlled lab replay.)",
                "remediation": "Enforce role checks in the API gateway and service layer.",
                "confidence": 0.96,
                "evidence": {"type": "lab_replay", "method": "GET", "url": "https://lab-api.lab.local/v1/admin/users", "response_status": 200, "expected": 403},
            },
            {
                "title": "Missing Rate Limiting on Login Endpoint",
                "severity": "MEDIUM",
                "cwe": "CWE-307",
                "category": "Authentication",
                "endpoint": "https://lab-api.lab.local/v1/auth/login",
                "cvss": 5.3,
                "description": "Brute-force protection is absent. (Controlled lab replay.)",
                "remediation": "Add per-account and per-IP rate limits.",
                "confidence": 0.88,
                "evidence": {"type": "lab_replay", "method": "POST", "url": "https://lab-api.lab.local/v1/auth/login", "attempts": 200, "blocked_after": None},
            },
        ],
    },
    "cloud_exposure": {
        "title": "Cloud Configuration Exposure",
        "mitre": ["T1190", "T1530"],
        "stages": [
            {"stage": "Recon", "technique": "T1595", "events": [("cloud:public_bucket_probe", "medium")]},
            {"stage": "Initial Access", "technique": "T1190", "events": [("cloud:anonymous_read", "high")]},
            {"stage": "Collection", "technique": "T1530", "events": [("data:sensitive_access", "critical")]},
        ],
        "findings": [
            {
                "title": "Publicly Readable Storage Bucket",
                "severity": "HIGH",
                "cwe": "CWE-1188",
                "category": "Cloud Configuration",
                "endpoint": "https://lab-bucket.s3.amazonaws.com/",
                "cvss": 7.5,
                "description": "Storage bucket allows anonymous list/read. (Controlled lab replay.)",
                "remediation": "Block public access and apply least-privilege bucket policies.",
                "confidence": 0.95,
                "evidence": {"type": "lab_replay", "url": "https://lab-bucket.s3.amazonaws.com/", "anonymous_list": True, "objects_exposed": 12},
            },
        ],
    },
    "secret_exposure": {
        "title": "Secret Exposure in Repository",
        "mitre": ["T1552"],
        "stages": [
            {"stage": "Recon", "technique": "T1595", "events": [("repo:clone", "low")]},
            {"stage": "Credential Access", "technique": "T1552", "events": [("repo:secret_scan_hit", "high")]},
            {"stage": "Collection", "technique": "T1005", "events": [("data:credential_use", "high")]},
        ],
        "findings": [
            {
                "title": "Hardcoded API Credential in Repository",
                "severity": "CRITICAL",
                "cwe": "CWE-798",
                "category": "Secret Exposure",
                "endpoint": "sentinelx-lab/lab-app/.env.example",
                "cvss": 9.8,
                "description": "A live API credential was committed to the repository. (Controlled lab replay.)",
                "remediation": "Rotate the credential and purge it from git history.",
                "confidence": 0.98,
                "evidence": {"type": "lab_replay", "file": "lab-app/.env.example", "secret_redacted": True, "rule": "aws-access-token"},
            },
        ],
    },
    "detection_gap": {
        "title": "Detection Gap — Undetected Lateral Movement",
        "mitre": ["T1021", "T1078"],
        "stages": [
            {"stage": "Recon", "technique": "T1595", "events": [("network:port_scan", "low")]},
            {"stage": "Initial Access", "technique": "T1078", "events": [("authentication:login_attempt", "medium")]},
            {"stage": "Lateral Movement", "technique": "T1021", "events": [("network:internal_connection", "high")]},
            {"stage": "Collection", "technique": "T1005", "events": [("data:sensitive_access", "critical")]},
        ],
        "findings": [
            {
                "title": "Lateral Movement Not Correlated by Detection Stack",
                "severity": "MEDIUM",
                "cwe": "CWE-778",
                "category": "Detection Gap",
                "endpoint": None,
                "cvss": 4.0,
                "description": "The event sequence reaches a sensitive resource without any deployed rule firing. (Controlled lab replay.)",
                "remediation": "Deploy the proposed correlation rule for internal connections to sensitive zones.",
                "confidence": 0.85,
                "evidence": {"type": "lab_replay", "note": "no rule matched the internal_connection sequence"},
            },
        ],
    },
    "security_regression": {
        "title": "Security Regression — Fixed Authorization Boundary",
        "mitre": ["T1190"],
        "stages": [
            {"stage": "Recon", "technique": "T1595", "events": [("web:api_request", "low")]},
            {"stage": "Initial Access", "technique": "T1190", "events": [("web:api_request", "high")]},
        ],
        "findings": [
            {
                "title": "SEC-REG: Authorization boundary regression (re-introduced)",
                "severity": "HIGH",
                "cwe": "CWE-639",
                "category": "Security Regression",
                "endpoint": "https://lab-web.lab.local/api/orders/1042",
                "cvss": 8.1,
                "description": "Deployment v3.4 re-introduced the previously fixed object-level authorization flaw. (Controlled lab replay.)",
                "remediation": "Re-apply server-side ownership checks and add a regression test to CI.",
                "confidence": 0.97,
                "evidence": {"type": "lab_replay", "deployment": "v3.4", "retest": "FAILED", "note": "regression test SEC-REG-1042 failed"},
            },
        ],
    },
}


class LabRangeAdapter(ToolAdapter):
    name = "lab-range"
    category = "lab"
    description = "Controlled cyber-range replay (DEMO DATA — never live targets)"

    def health_check(self) -> dict[str, Any]:
        # Pure-Python adapter — always available, no external binary required.
        return {"name": self.name, "installed": True, "version": "builtin", "health": "OK"}

    def validate_scope(self, db: Session, engagement, target_ref: str, asset=None) -> None:
        super().validate_scope(db, engagement, target_ref, asset=asset)
        # Hard boundary: only lab-range targets may be replayed.
        lab = settings.LAB_CIDR
        candidate_ips: list[str] = []
        if asset and asset.ip_address:
            candidate_ips.append(asset.ip_address)
        if target_ref:
            candidate_ips.append(target_ref)
        from ...services.scope_engine import _rule_matches  # reuse CIDR matcher
        from ...models import ScopeRule

        probe = ScopeRule(kind="INCLUDE", match_type="CIDR", value=lab)
        if not any(_rule_matches(probe, c) for c in candidate_ips):
            raise AdapterError(
                f"Lab-range adapter refuses target outside {lab}: {target_ref}. "
                "Only authorized cyber-range targets may be replayed."
            )

    def execute(self, request: dict[str, Any]) -> dict[str, Any]:
        scenario_name = request["params"].get("scenario", "web_app_authorization")
        scenario = SCENARIOS.get(scenario_name)
        if scenario is None:
            raise AdapterError(f"Unknown lab scenario: {scenario_name}")
        return {
            "scenario": scenario,
            "scenario_name": scenario_name,
            "target": request["target"],
            "replay_id": hashlib.sha256(f"{scenario_name}:{request['target']}".encode()).hexdigest()[:16],
        }

    def parse_output(self, raw: dict[str, Any]) -> dict[str, Any]:
        return raw

    def normalize_result(self, parsed: dict[str, Any]) -> dict[str, Any]:
        scenario = parsed["scenario"]
        base_ts = datetime.now(timezone.utc)
        events: list[NormalizedEvent] = []
        for i, stage in enumerate(scenario["stages"]):
            for j, (etype, sev) in enumerate(stage["events"]):
                ts = base_ts + timedelta(seconds=30 * i + j * 5)
                events.append(
                    NormalizedEvent(
                        event_type=etype,
                        severity=sev,
                        timestamp=ts,
                        asset_ip=parsed["target"] if "." in parsed["target"] else None,
                        metadata={
                            "stage": stage["stage"],
                            "technique": stage["technique"],
                            "lab": True,
                            "demo": True,
                            "label": DEMO_LABEL,
                            "replay_id": parsed["replay_id"],
                        },
                    )
                )
        findings: list[NormalizedFinding] = []
        for f in scenario["findings"]:
            findings.append(
                NormalizedFinding(
                    title=f["title"],
                    severity=f["severity"],
                    description=f["description"] + f" [{LAB_LABEL}]",
                    cwe=f.get("cwe"),
                    category=f.get("category"),
                    endpoint=f.get("endpoint"),
                    cvss=f.get("cvss"),
                    remediation=f.get("remediation"),
                    confidence=f.get("confidence", 0.9),
                    asset_ip=parsed["target"] if "." in parsed["target"] else None,
                    evidence={
                        **f.get("evidence", {}),
                        "label": LAB_LABEL,
                        "demo": True,
                        "replay_id": parsed["replay_id"],
                        "scenario": parsed["scenario_name"],
                    },
                )
            )
        return {
            "assets": [],
            "services": [],
            "findings": findings,
            "events": events,
            "meta": {
                "scenario": parsed["scenario_name"],
                "title": scenario["title"],
                "mitre": scenario["mitre"],
                "label": LAB_LABEL,
                "demo": True,
                "replay_id": parsed["replay_id"],
            },
        }
