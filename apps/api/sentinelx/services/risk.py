"""Business Risk Engine.

Risk is not CVSS alone. It combines technical severity, exposure,
exploitability, asset criticality, identity privilege, attack-path position,
data sensitivity, detection coverage and business impact — and explains the
score.
"""
from __future__ import annotations

from typing import Any

from ..models import Asset, Finding

SEVERITY_BASE = {"CRITICAL": 95, "HIGH": 75, "MEDIUM": 50, "LOW": 25, "INFO": 5}
CRITICALITY_WEIGHT = {"CRITICAL": 1.25, "HIGH": 1.12, "MEDIUM": 1.0, "LOW": 0.85}
EXPOSURE_WEIGHT = {"INTERNET_FACING": 1.2, "EXTERNAL": 1.1, "INTERNAL": 1.0, "UNKNOWN": 1.0}
EXPLOITABILITY_WEIGHT = {
    "EASY": 1.25, "MODERATE": 1.1, "DIFFICULT": 0.9, "UNKNOWN": 1.0,
}


def score_finding(finding: Finding, asset: Asset | None = None, detection_coverage: float = 0.5) -> dict[str, Any]:
    """Compute a 0-100 business risk score with an explanation."""
    technical = SEVERITY_BASE.get(finding.severity.upper(), 50)
    if finding.cvss is not None:
        technical = max(technical, finding.cvss * 10)

    asset_criticality = (asset.criticality if asset else "MEDIUM") or "MEDIUM"
    exposure = (asset.exposure if asset else "UNKNOWN") or "UNKNOWN"
    exploitability = (finding.exploitability or "UNKNOWN").upper()

    weight = (
        CRITICALITY_WEIGHT.get(asset_criticality, 1.0)
        * EXPOSURE_WEIGHT.get(exposure, 1.0)
        * EXPLOITABILITY_WEIGHT.get(exploitability, 1.0)
    )
    # Detection coverage lowers the residual risk (defenders see it coming).
    detection_factor = 1.0 - (0.25 * max(0.0, min(1.0, detection_coverage)))
    business = min(100.0, round(technical * weight * detection_factor, 1))

    parts: list[str] = [
        f"technical severity {finding.severity} ({technical:.0f}/100)",
        f"asset criticality {asset_criticality}",
        f"exposure {exposure}",
        f"exploitability {exploitability}",
        f"detection coverage {detection_coverage:.0%}",
    ]
    return {
        "score": business,
        "technical": round(technical, 1),
        "asset_criticality": asset_criticality,
        "exposure": exposure,
        "exploitability": exploitability,
        "detection_coverage": detection_coverage,
        "explanation": "Risk = technical severity × criticality × exposure × exploitability × (1 − 0.25×detection). "
                       + "; ".join(parts),
    }


def score_path(attack_path: Any, findings_by_asset: dict[str, list[Finding]]) -> dict[str, Any]:
    """Score an attack path from its nodes' findings and destination criticality."""
    node_findings: list[Finding] = []
    for node in attack_path.nodes:
        if node.asset_id:
            node_findings.extend(findings_by_asset.get(node.asset_id, []))
    if not node_findings:
        return {"score": 0.0, "explanation": "No findings on path"}
    worst = max(SEVERITY_BASE.get(f.severity.upper(), 50) for f in node_findings)
    validated_bonus = 1.15 if any(f.validated for f in node_findings) else 1.0
    depth_penalty = max(1.0, len(attack_path.nodes) * 0.12)
    dest = None
    for node in reversed(attack_path.nodes):
        if node.asset_id:
            dest = node.asset_id
            break
    score = min(100.0, round((worst * validated_bonus) / depth_penalty, 1))
    return {
        "score": score,
        "worst_finding_severity": worst,
        "validated": any(f.validated for f in node_findings),
        "depth": len(attack_path.nodes),
        "explanation": (
            f"worst finding severity {worst:.0f}/100 × {'validated' if any(f.validated for f in node_findings) else 'unvalidated'} "
            f"÷ depth penalty {depth_penalty:.2f}"
        ),
    }
