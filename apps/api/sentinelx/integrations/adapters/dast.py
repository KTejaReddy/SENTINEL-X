"""Dynamic application security testing (DAST) adapter.

Performs REAL HTTP requests against an authorized target (the controlled
cyber-range or any in-scope customer-owned endpoint) and turns the actual
responses into evidence-backed findings. No simulated results: every finding
records the method/URL, request context, response status and a response
excerpt that confirms the condition.

Targets are always validated by the scope/policy gate before `run()`; the
adapter itself never contacts anything but the configured lab/customer URLs.
"""
from __future__ import annotations

import json
from typing import Any

import httpx

from ..base import NormalizedFinding, ToolAdapter

WEAK_CREDENTIALS = [
    ("alice", "alice"),
    ("admin", "admin"),
    ("admin", "password"),
]
LEAKED_SERVICE_TOKEN = "lab-service-token-2026"  # documented lab weakness


def _json_has(body: str, **fields) -> bool:
    """True if the response body is JSON containing the given field values."""
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, TypeError):
        return False
    return all(data.get(k) == v for k, v in fields.items())


WEB_PROBES = ["server_fingerprint", "missing_security_headers", "weak_credentials", "idor", "broken_functional_auth", "source_disclosure"]
API_PROBES = ["bola", "leaked_token_bfa", "no_rate_limit"]


class DastAdapter(ToolAdapter):
    name = "dast"
    category = "dast"
    description = "HTTP DAST probe — real requests against authorized targets (lab web/api)"

    def health_check(self) -> dict[str, Any]:
        # Builtin adapter: always available; reachability is reported per-run.
        return {"name": self.name, "installed": True, "version": "builtin-http-probe", "health": "OK", "builtin": True}

    # ---- execution ----

    def execute(self, request: dict[str, Any]) -> str:
        base_url = (request.get("params") or {}).get("base_url") or (request.get("target") or "")
        api_base = (request.get("params") or {}).get("api_base_url")
        probe_set = (request.get("params") or {}).get("probe_set", "full")
        results: list[dict[str, Any]] = []

        if probe_set in ("full", "web"):
            results.extend(self._probe_web(base_url))
        if probe_set in ("full", "api") and api_base:
            results.extend(self._probe_api(api_base))

        return json.dumps({"tool": self.name, "results": results, "probes_executed": len(results)})

    def parse_output(self, raw: str) -> list[dict[str, Any]]:
        try:
            data = json.loads(raw)
            self._last_probes = data.get("probes_executed", 0)
            return data.get("results", [])
        except (json.JSONDecodeError, AttributeError):
            self._last_probes = 0
            return []

    def normalize_result(self, parsed: list[dict[str, Any]]) -> dict[str, Any]:
        probes = getattr(self, "_last_probes", len(parsed))
        findings: list[NormalizedFinding] = []
        for probe in parsed:
            if not probe.get("finding"):
                continue
            findings.append(
                NormalizedFinding(
                    title=probe["finding"]["title"],
                    severity=probe["finding"]["severity"],
                    description=probe["finding"]["description"],
                    cwe=probe["finding"].get("cwe"),
                    category="Web Application",
                    endpoint=probe.get("url"),
                    confidence=probe.get("confidence", 0.8),
                    remediation=probe["finding"].get("remediation"),
                    evidence={
                        "type": "http_probe",
                        "probe": probe.get("probe"),
                        "method": probe.get("method"),
                        "url": probe.get("url"),
                        "response_status": probe.get("response_status"),
                        "response_excerpt": probe.get("response_excerpt", "")[:400],
                        "confirmed_by": probe.get("confirmed_by"),
                    },
                )
            )
        return {
            "assets": [],
            "services": [],
            "findings": findings,
            "events": [],
            "meta": {"tool": "dast", "demo": False, "probes_executed": probes, "target_unreachable": probes == 0},
        }

    # ---- probes (all real HTTP) ----

    @staticmethod
    def _get(client: httpx.Client, url: str) -> dict[str, Any]:
        try:
            resp = client.get(url, timeout=6, follow_redirects=True)
            body = resp.text[:400]
            return {"status": resp.status_code, "headers": dict(resp.headers), "body": body}
        except httpx.HTTPError as exc:
            return {"status": None, "headers": {}, "body": "", "error": str(exc)}

    @staticmethod
    def _post(client: httpx.Client, url: str, json_body: dict) -> dict[str, Any]:
        try:
            resp = client.post(url, json=json_body, timeout=6, follow_redirects=True)
            return {"status": resp.status_code, "headers": dict(resp.headers), "body": resp.text[:400]}
        except httpx.HTTPError as exc:
            return {"status": None, "headers": {}, "body": "", "error": str(exc)}

    def _probe_web(self, base_url: str) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        if not base_url:
            return results
        base = base_url.rstrip("/")
        with httpx.Client() as client:
            # 1. Server fingerprint
            r = self._get(client, f"{base}/")
            if r["status"] is not None:
                server = r["headers"].get("server") or ""
                results.append(
                    {
                        "probe": "server_fingerprint",
                        "method": "GET",
                        "url": f"{base}/",
                        "response_status": r["status"],
                        "response_excerpt": r["body"][:120],
                        "finding": {
                            "title": "Web server fingerprint exposed",
                            "severity": "LOW",
                            "description": f"Response exposes server fingerprint: {server or 'unknown'}.",
                            "remediation": "Suppress verbose server headers.",
                        },
                    }
                )
                # 2. Missing security headers
                missing = [h for h in ("content-security-policy", "strict-transport-security", "x-frame-options", "x-content-type-options") if h not in r["headers"]]
                if missing:
                    results.append(
                        {
                            "probe": "missing_security_headers",
                            "method": "GET",
                            "url": f"{base}/",
                            "response_status": r["status"],
                            "response_excerpt": f"missing={missing}",
                            "finding": {
                                "title": "Missing security headers",
                                "severity": "LOW",
                                "description": f"Response missing: {', '.join(missing)}.",
                                "remediation": "Add CSP, HSTS, X-Frame-Options and X-Content-Type-Options headers.",
                            },
                        }
                    )

            # 3. Weak/default credentials
            for user, password in WEAK_CREDENTIALS:
                resp = self._post(client, f"{base}/login", {"username": user, "password": password})
                if resp["status"] == 200:
                    results.append(
                        {
                            "probe": "weak_credentials",
                            "method": "POST",
                            "url": f"{base}/login",
                            "response_status": resp["status"],
                            "response_excerpt": resp["body"][:120],
                            "confirmed_by": f"login succeeded with {user}/{password}",
                            "confidence": 0.95,
                            "finding": {
                                "title": f"Weak/default credentials accepted: {user}",
                                "severity": "HIGH",
                                "description": f"The application accepted login with weak credentials {user}/{password}.",
                                "cwe": "CWE-798",
                                "remediation": "Enforce strong, unique credentials and account lockout.",
                            },
                        }
                    )
                    break

            # 4. IDOR — authenticated cross-customer order read
            login = self._post(client, f"{base}/login", {"username": "alice", "password": "alice"})
            if login["status"] == 200:
                alice = httpx.Client()
                for c in client.cookies.jar:
                    alice.cookies.set(c.name, c.value, domain=c.domain, path=c.path)
                r2 = self._get(alice, f"{base}/orders/2")  # bob's order
                if r2["status"] == 200 and _json_has(r2["body"], customer="bob"):
                    results.append(
                        {
                            "probe": "idor",
                            "method": "GET",
                            "url": f"{base}/orders/2",
                            "response_status": r2["status"],
                            "response_excerpt": r2["body"][:120],
                            "confirmed_by": "alice read bob's order",
                            "confidence": 0.97,
                            "finding": {
                                "title": "Insecure Direct Object Reference (IDOR) on order records",
                                "severity": "HIGH",
                                "description": "An authenticated low-privilege user (alice) can read another customer's order (bob) by ID.",
                                "cwe": "CWE-639",
                                "remediation": "Enforce server-side ownership checks on every object access.",
                            },
                        }
                    )
                # 5. Broken function-level authorization
                r3 = self._get(alice, f"{base}/admin")
                if r3["status"] == 200 and "admin" in r3["body"]:
                    results.append(
                        {
                            "probe": "broken_functional_auth",
                            "method": "GET",
                            "url": f"{base}/admin",
                            "response_status": r3["status"],
                            "response_excerpt": r3["body"][:120],
                            "confirmed_by": "alice reached /admin",
                            "confidence": 0.97,
                            "finding": {
                                "title": "Broken function-level authorization: /admin reachable by non-admin",
                                "severity": "HIGH",
                                "description": "Any authenticated user can reach the admin panel.",
                                "cwe": "CWE-862",
                                "remediation": "Enforce role-based checks on admin functions.",
                            },
                        }
                    )
                alice.close()

            # 6. Source / debug endpoint disclosure
            for path in ("/.git/config", "/debug", "/actuator", "/.env"):
                r = self._get(client, f"{base}{path}")
                if r["status"] == 200:
                    results.append(
                        {
                            "probe": "source_disclosure",
                            "method": "GET",
                            "url": f"{base}{path}",
                            "response_status": r["status"],
                            "response_excerpt": r["body"][:120],
                            "confidence": 0.9,
                            "finding": {
                                "title": f"Sensitive endpoint exposed: {path}",
                                "severity": "MEDIUM",
                                "description": f"Path {path} returned HTTP 200 (expected 404).",
                                "cwe": "CWE-538",
                                "remediation": "Remove or lock down debug/source-control endpoints.",
                            },
                        }
                    )
                    break
        return results

    def _probe_api(self, api_base: str) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        base = api_base.rstrip("/")
        with httpx.Client() as client:
            # 7. BOLA — cross-customer order read via spoofable identity header
            r_own = self._get(client, f"{base}/orders/1")
            r_other = client.get(f"{base}/orders/5", headers={"X-User": "alice"}, timeout=6)
            if r_other.status_code == 200 and _json_has(r_other.text, customer="erin") and r_own["status"] == 200:
                results.append(
                    {
                        "probe": "bola",
                        "method": "GET",
                        "url": f"{base}/orders/5",
                        "response_status": r_other.status_code,
                        "response_excerpt": r_other.text[:120],
                        "confirmed_by": "alice read erin's order via spoofed X-User header",
                        "confidence": 0.97,
                        "finding": {
                            "title": "Broken Object-Level Authorization (BOLA) on API orders",
                            "severity": "HIGH",
                            "description": "The API trusts a client-supplied identity header; any caller can read any order.",
                            "cwe": "CWE-639",
                            "remediation": "Derive identity server-side; enforce ownership on every object access.",
                        },
                    }
                )
            # 8. Leaked service token + BFLA
            no_token = self._get(client, f"{base}/admin/users")
            with_token = client.get(f"{base}/admin/users", headers={"Authorization": f"Bearer {LEAKED_SERVICE_TOKEN}"}, timeout=6)
            if no_token["status"] == 401 and with_token.status_code == 200:
                results.append(
                    {
                        "probe": "leaked_token_bfa",
                        "method": "GET",
                        "url": f"{base}/admin/users",
                        "response_status": with_token.status_code,
                        "response_excerpt": with_token.text[:120],
                        "confirmed_by": "admin API callable with leaked service token",
                        "confidence": 0.97,
                        "finding": {
                            "title": "Leaked service token grants admin (BFLA)",
                            "severity": "HIGH",
                            "description": "A leaked, hardcoded service token grants admin API access without role checks.",
                            "cwe": "CWE-798",
                            "remediation": "Rotate the token, remove it from source, enforce role-based authorization.",
                        },
                    }
                )
            # 9. No rate limiting on search
            codes = [client.get(f"{base}/search", params={"q": f"q{i}"}, timeout=6).status_code for i in range(12)]
            if codes and all(c == 200 for c in codes):
                results.append(
                    {
                        "probe": "no_rate_limit",
                        "method": "GET",
                        "url": f"{base}/search",
                        "response_status": codes[-1],
                        "response_excerpt": f"12/12 requests returned 200",
                        "finding": {
                            "title": "Missing rate limiting on /search",
                            "severity": "MEDIUM",
                            "description": "12 rapid unauthenticated requests all succeeded — no throttling observed.",
                            "cwe": "CWE-799",
                            "remediation": "Add per-IP and per-account rate limits.",
                        },
                    }
                )
        return results
