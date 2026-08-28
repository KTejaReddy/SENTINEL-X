"""Controlled Security Exercise orchestrator.

RUN CONTROLLED SECURITY EXERCISE executes an approved, in-scope lab workflow
through the real pipeline: engagement → recon → scan → validate → attack path
→ blue detection → incident → response → remediation → retest.

Everything runs through jobs and the policy engine; the lab-range adapter
refuses targets outside the authorized lab CIDR. All artifacts are labeled
CONTROLLED LAB / DEMO DATA.
"""
from __future__ import annotations

from datetime import date, datetime, timedelta, timezone
from typing import Any, Optional

from sqlalchemy.orm import Session

from ..models import Asset, Engagement, Finding, Incident, ScopeRule, User
from .jobs import enqueue_job

EXERCISE_SCENARIOS = {
    "web_app_authorization": {
        "title": "Public Web Application — Broken Object-Level Authorization",
        "lab_assets": ["lab-web", "lab-api", "lab-db", "lab-admin"],
        "tools": ["lab-range"],
        "validate": True,
        "purple": True,
    },
    "api_authorization": {
        "title": "API Authorization Weakness",
        "lab_assets": ["lab-api", "lab-db"],
        "tools": ["lab-range"],
        "validate": True,
        "purple": True,
    },
    "cloud_exposure": {
        "title": "Cloud Configuration Exposure",
        "lab_assets": ["lab-cloud-bucket", "lab-api"],
        "tools": ["lab-range"],
        "validate": False,
        "purple": True,
    },
    "secret_exposure": {
        "title": "Secret Exposure in Repository",
        "lab_assets": ["lab-repo", "lab-api"],
        "tools": ["lab-range"],
        "validate": False,
        "purple": True,
    },
    "detection_gap": {
        "title": "Detection Gap",
        "lab_assets": ["lab-web", "lab-db", "lab-admin"],
        "tools": ["lab-range"],
        "validate": False,
        "purple": True,
    },
    "security_regression": {
        "title": "Security Regression",
        "lab_assets": ["lab-web", "lab-api"],
        "tools": ["lab-range"],
        "validate": False,
        "purple": False,
    },
}


def _get_or_create_lab_engagement(db: Session, org_id: str, scenario: str, user: User | None) -> Engagement:
    name = f"EX-{scenario} — {EXERCISE_SCENARIOS[scenario]['title']}"
    existing = (
        db.query(Engagement)
        .filter(Engagement.org_id == org_id, Engagement.name == name, Engagement.status.in_(["APPROVED", "RUNNING", "COMPLETED", "PAUSED"]))
        .first()
    )
    if existing:
        return existing
    engagement = Engagement(
        org_id=org_id,
        name=name,
        description=f"Controlled lab exercise for {EXERCISE_SCENARIOS[scenario]['title']} [CONTROLLED LAB]",
        status="APPROVED",
        start_date=date.today() - timedelta(days=1),
        end_date=date.today() + timedelta(days=30),
        config={
            "allowed_tools": ["lab-range", "nmap", "nuclei"],
            "max_request_rate": 20,
            "destructive_testing": False,
            "data_handling": "no_pii",
            "lab_only": True,
        },
        approved_by=user.id if user else None,
        approved_at=datetime.now(timezone.utc),
        created_by=user.id if user else None,
        source="exercise",
    )
    db.add(engagement)
    db.flush()
    db.add(ScopeRule(org_id=org_id, engagement_id=engagement.id, kind="INCLUDE", match_type="CIDR", value="10.10.10.0/24", note="Controlled lab range"))
    db.add(ScopeRule(org_id=org_id, engagement_id=engagement.id, kind="EXCLUDE", match_type="CIDR", value="10.0.0.0/16", note="Production network excluded from lab engagements"))
    db.commit()
    db.refresh(engagement)
    return engagement


def run_exercise(db: Session, org_id: str, scenario: str, user: User | None = None) -> dict[str, Any]:
    if scenario not in EXERCISE_SCENARIOS:
        raise ValueError(f"Unknown scenario: {scenario}")
    spec = EXERCISE_SCENARIOS[scenario]
    engagement = _get_or_create_lab_engagement(db, org_id, scenario, user)

    # Resolve lab assets by name
    assets = db.query(Asset).filter(Asset.org_id == org_id, Asset.name.in_(spec["lab_assets"])).all()
    entry_asset = next((a for a in assets if a.asset_type in {"WEB_APPLICATION", "API"} or a.name == "lab-web"), None) or (assets[0] if assets else None)
    target_ref = entry_asset.ip_address or entry_asset.id if entry_asset else None

    jobs: list[dict[str, Any]] = []
    job = enqueue_job(
        db, org_id=org_id, engagement_id=engagement.id, kind="scan", tool="lab-range",
        target_ref=target_ref, params={"scenario": scenario},
        created_by=user.id if user else None, demo=True,
    )
    jobs.append({"kind": "scan", "job_id": job.id, "description": "Attack surface discovery + finding generation"})

    return {
        "engagement_id": engagement.id,
        "scenario": scenario,
        "title": spec["title"],
        "jobs": jobs,
        "label": "CONTROLLED LAB",
        "demo": True,
        "note": "All artifacts from this exercise are labeled DEMO DATA / CONTROLLED LAB.",
    }
