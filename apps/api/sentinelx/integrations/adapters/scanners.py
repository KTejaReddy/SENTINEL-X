"""Additional scanner adapters: ZAP, Semgrep, Gitleaks, Trivy."""
from __future__ import annotations

import json
from typing import Any

from ..base import NormalizedFinding, ToolAdapter, ToolNotInstalled, run_cli


class ZapAdapter(ToolAdapter):
    """OWASP ZAP DAST adapter (HTTP API).

    Requires a running ZAP instance. When unavailable the adapter is healthy
    with status NOT_INSTALLED and the platform degrades gracefully.
    """
    name = "zap"
    category = "scanner"
    description = "OWASP ZAP web application scanner (API)"

    def health_check(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "installed": self._binary_available(),
            "version": None,
            "health": "OK" if self._binary_available() else "NOT_INSTALLED",
        }

    def execute(self, request: dict[str, Any]) -> str:
        raise ToolNotInstalled(
            "ZAP integration requires a running ZAP instance; configure ZAP_URL. "
            "Until then use the lab-range adapter for controlled web tests."
        )

    def parse_output(self, raw: Any) -> list[dict[str, Any]]:
        return []

    def normalize_result(self, parsed: list[dict[str, Any]]) -> dict[str, Any]:
        return {"assets": [], "services": [], "findings": [], "events": []}


class SemgrepAdapter(ToolAdapter):
    name = "semgrep"
    category = "sast"
    description = "Static analysis security testing (Semgrep JSON output)"

    def build_request(self, target: str, params: dict[str, Any]) -> dict[str, Any]:
        cmd = [self._binary_path(), "scan", "--json", "--quiet", "--output", "-"]
        if params.get("config"):
            cmd += ["--config", str(params["config"])]
        cmd.append(target)
        return {"cmd": cmd, "target": target, "params": params}

    def execute(self, request: dict[str, Any]) -> str:
        if not self._binary_available():
            raise ToolNotInstalled("semgrep is not installed")
        proc = run_cli(request["cmd"], timeout=int(request["params"].get("timeout", 600)))
        if proc.returncode not in (0, 1):
            raise ToolNotInstalled(f"semgrep failed: {proc.stderr[:400]}")
        return proc.stdout

    def parse_output(self, raw: str) -> list[dict[str, Any]]:
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return []
        return data.get("results", [])

    def normalize_result(self, parsed: list[dict[str, Any]]) -> dict[str, Any]:
        findings: list[NormalizedFinding] = []
        for r in parsed:
            findings.append(
                NormalizedFinding(
                    title=r.get("check_id", "semgrep finding"),
                    severity=(r.get("extra", {}).get("severity") or "WARNING").upper(),
                    description=(r.get("extra", {}).get("message") or "")[:2000],
                    cwe=(r.get("extra", {}).get("metadata", {}) or {}).get("cwe", [None])[0] if isinstance((r.get("extra", {}).get("metadata", {}) or {}).get("cwe"), list) else None,
                    category="Source Code",
                    endpoint=f"{r.get('path')}:{r.get('start', {}).get('line')}",
                    confidence=0.8,
                    evidence={
                        "type": "semgrep_result",
                        "path": r.get("path"),
                        "lines": r.get("extra", {}).get("lines", "")[:500],
                    },
                )
            )
        return {"assets": [], "services": [], "findings": findings, "events": []}


class GitleaksAdapter(ToolAdapter):
    name = "gitleaks"
    category = "secrets"
    description = "Secret scanning for repositories (Gitleaks JSON output)"

    def build_request(self, target: str, params: dict[str, Any]) -> dict[str, Any]:
        cmd = [self._binary_path(), "detect", "--source", target, "--report-format", "json", "--report-path", "-", "--no-banner"]
        if params.get("log_opts"):
            cmd += ["--log-opts", str(params["log_opts"])]
        return {"cmd": cmd, "target": target, "params": params}

    def execute(self, request: dict[str, Any]) -> str:
        if not self._binary_available():
            raise ToolNotInstalled("gitleaks is not installed")
        proc = run_cli(request["cmd"], timeout=int(request["params"].get("timeout", 300)))
        if proc.returncode not in (0, 1):
            raise ToolNotInstalled(f"gitleaks failed: {proc.stderr[:400]}")
        return proc.stdout

    def parse_output(self, raw: str) -> list[dict[str, Any]]:
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return []
        return data if isinstance(data, list) else []

    def normalize_result(self, parsed: list[dict[str, Any]]) -> dict[str, Any]:
        findings: list[NormalizedFinding] = []
        for item in parsed:
            findings.append(
                NormalizedFinding(
                    title=f"Secret exposure: {item.get('RuleID')} in {item.get('File')}",
                    severity="HIGH",
                    description=f"Secret leaked in {item.get('File')} (commit {str(item.get('Commit'))[:8]}).",
                    category="Secret Exposure",
                    cwe="CWE-798",
                    endpoint=item.get("File"),
                    confidence=0.9,
                    remediation="Rotate the credential immediately and purge it from history.",
                    evidence={
                        "type": "gitleaks_result",
                        "file": item.get("File"),
                        "rule": item.get("RuleID"),
                        "commit": item.get("Commit"),
                        "start_line": item.get("StartLine"),
                        # Never store the actual secret value in the finding.
                        "secret_redacted": bool(item.get("Secret")),
                    },
                )
            )
        return {"assets": [], "services": [], "findings": findings, "events": []}


class TrivyAdapter(ToolAdapter):
    name = "trivy"
    category = "container"
    description = "Container and dependency vulnerability scanner (Trivy JSON)"

    def build_request(self, target: str, params: dict[str, Any]) -> dict[str, Any]:
        cmd = [self._binary_path(), "image", "--format", "json", "--output", "-", "--quiet", target]
        if params.get("severity"):
            cmd += ["--severity", str(params["severity"])]
        return {"cmd": cmd, "target": target, "params": params}

    def execute(self, request: dict[str, Any]) -> str:
        if not self._binary_available():
            raise ToolNotInstalled("trivy is not installed")
        proc = run_cli(request["cmd"], timeout=int(request["params"].get("timeout", 600)))
        if proc.returncode not in (0, 1):
            raise ToolNotInstalled(f"trivy failed: {proc.stderr[:400]}")
        return proc.stdout

    def parse_output(self, raw: str) -> list[dict[str, Any]]:
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return []
        results: list[dict[str, Any]] = []
        for target in data.get("Results", []):
            for vuln in target.get("Vulnerabilities", []):
                results.append({"target": target.get("Target"), "vuln": vuln})
        return results

    def normalize_result(self, parsed: list[dict[str, Any]]) -> dict[str, Any]:
        findings: list[NormalizedFinding] = []
        for item in parsed:
            v = item["vuln"]
            findings.append(
                NormalizedFinding(
                    title=f"{v.get('VulnerabilityID')}: {v.get('Title', '')[:120]}",
                    severity=(v.get("Severity") or "UNKNOWN").upper(),
                    description=f"Vulnerable package {v.get('PkgName')} {v.get('InstalledVersion')} in {item['target']}. Fixed in {v.get('FixedVersion')}.",
                    cve=v.get("VulnerabilityID"),
                    cwe=None,
                    category="Container",
                    cvss=v.get("CVSS", {}).get("nvd", {}).get("V3Score"),
                    remediation=f"Upgrade {v.get('PkgName')} to {v.get('FixedVersion')}",
                    confidence=0.85,
                    endpoint=item["target"],
                    evidence={"type": "trivy_result", "pkg": v.get("PkgName"), "installed": v.get("InstalledVersion"), "fixed": v.get("FixedVersion")},
                )
            )
        return {"assets": [], "services": [], "findings": findings, "events": []}
