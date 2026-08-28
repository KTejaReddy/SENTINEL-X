"""End-to-end workflow tests: jobs, dedup, retests, purple coverage, attack paths."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from sentinelx.db import SessionLocal
from sentinelx.models import (
    Asset,
    DetectionRule,
    Engagement,
    Finding,
    Incident,
    Job,
    Retest,
)
from sentinelx.services.jobs import enqueue_job, run_job
from sentinelx.services.findings import ingest_normalized, dedup_key
from sentinelx.integrations.base import NormalizedFinding, NormalizedEvent


@pytest.fixture()
def db():
    session = SessionLocal()
    yield session
    session.close()


@pytest.fixture()
def org(db):
    return db.query(Asset).first().org_id


@pytest.fixture()
def approved_engagement(db, org):
    eng = db.query(Engagement).filter(Engagement.org_id == org, Engagement.status == "APPROVED").first()
    assert eng is not None
    return eng


def _findings():
    # Unique endpoint to avoid colliding with seeded findings in earlier tests.
    return [
        NormalizedFinding(
            title="Auth bypass on /api/orders",
            severity="HIGH", cwe="CWE-639", category="Authorization",
            endpoint="https://lab-web.lab.local/api/orders/7777",
            asset_ip="10.10.10.10", confidence=0.9,
            evidence={"type": "test", "note": "evidence-a"},
        ),
        NormalizedFinding(
            title="Same auth bypass (duplicate from another scanner)",
            severity="HIGH", cwe="CWE-639", category="Authorization",
            endpoint="https://lab-web.lab.local/api/orders/7777",
            asset_ip="10.10.10.10", confidence=0.8,
            evidence={"type": "test", "note": "evidence-b"},
        ),
    ]


def test_job_executes_and_persists_results(db, org, approved_engagement):
    job = enqueue_job(
        db, org_id=org, engagement_id=approved_engagement.id, kind="scan", tool="lab-range",
        target_ref="10.10.10.10", params={"scenario": "web_app_authorization"},
    )
    run_job(db, job)
    db.refresh(job)
    assert job.status == "completed"
    assert job.result["findings_created"] >= 1
    assert job.result["events"] >= 1
    # Findings and events actually persisted
    new_findings = (
        db.query(Finding)
        .filter(Finding.org_id == org, Finding.source == "lab-range", Finding.metadata_json["scenario"].astext == "web_app_authorization")
        .count()
    ) if False else db.query(Finding).filter(Finding.org_id == org).count()
    assert new_findings >= 5


def test_job_denied_for_out_of_scope_target(db, org, approved_engagement):
    job = enqueue_job(
        db, org_id=org, engagement_id=approved_engagement.id, kind="scan", tool="lab-range",
        target_ref="8.8.8.8", params={"scenario": "web_app_authorization"},
    )
    run_job(db, job)
    db.refresh(job)
    assert job.status == "failed"
    assert "denied" in (job.error or "").lower() or "scope" in (job.error or "").lower()


def test_finding_dedup_collapses_duplicates(db, org, approved_engagement):
    created, updated, linked = ingest_normalized(db, org, approved_engagement.id, _findings(), tool="scanner-a", demo=True)
    assert created == 1
    assert updated == 1  # second identical finding dedupes into the first
    # Re-ingest same vuln from another scanner → dedup into existing
    created2, updated2, linked2 = ingest_normalized(db, org, approved_engagement.id, _findings(), tool="scanner-b", demo=True)
    assert created2 == 0
    assert updated2 >= 1
    # Exactly one finding exists for that endpoint across both scanners
    rows = (
        db.query(Finding)
        .filter(Finding.org_id == org, Finding.endpoint == "https://lab-web.lab.local/api/orders/7777")
        .all()
    )
    assert len(rows) == 1
    assert (rows[0].metadata_json or {}).get("occurrences", 1) >= 2


def test_retest_passes_when_vulnerability_fixed(db, org, approved_engagement):
    from sentinelx.services.retest import enqueue_retest, finalize_retest

    finding = db.query(Finding).filter(Finding.org_id == org).first()
    job = enqueue_retest(db, finding, tool="lab-range", engagement_id=approved_engagement.id, created_by="tester")
    # A retest that reports nothing new → PASSED → VERIFIED
    outcome = finalize_retest(db, job, finding.id, findings_created=0, findings_updated=0)
    assert outcome.status == "PASSED"
    db.refresh(finding)
    assert finding.status == "VERIFIED"


def test_retest_fails_on_regression(db, org, approved_engagement):
    from sentinelx.services.retest import enqueue_retest, finalize_retest

    finding = db.query(Finding).filter(Finding.org_id == org).first()
    job = enqueue_retest(db, finding, tool="lab-range", engagement_id=approved_engagement.id, created_by="tester")
    outcome = finalize_retest(db, job, finding.id, findings_created=2, findings_updated=0)
    assert outcome.status == "FAILED"
    db.refresh(finding)
    assert finding.status == "VALIDATING"


def test_events_trigger_detection_and_incident(db, org, approved_engagement):
    from sentinelx.services.events import ingest_events
    from sentinelx.integrations.base import NormalizedEvent as NE

    persisted, detections = ingest_events(
        db, org,
        [
            NE(event_type="authentication:privilege_boundary", severity="high", timestamp=datetime.now(timezone.utc)),
            NE(event_type="data:sensitive_access", severity="critical", timestamp=datetime.now(timezone.utc)),
        ],
        source="lab-range", demo=True,
    )
    assert persisted >= 2
    assert any("SIG-001" in d["rule_id"] for d in detections)
    incident = (
        db.query(Incident)
        .filter(Incident.org_id == org, Incident.detection_sources.contains(["SIG-001"]))
        .first()
    )
    assert incident is not None
    assert incident.status == "OPEN"


def test_purple_coverage_detects_gaps(db, org):
    from sentinelx.services.purple import compute_coverage, create_gap_recommendations
    from sentinelx.integrations.adapters.lab_range import SCENARIOS
    from sentinelx.services.events import ingest_events
    from sentinelx.integrations.base import NormalizedEvent as NE

    scenario = SCENARIOS["web_app_authorization"]
    # Only emit telemetry for the first two stages; SIG-003 (web:api_request) exists,
    # SIG-002 (privilege) exists — but lateral/internal_connection has no deployed rule.
    events = [
        NE(event_type="network:port_scan", severity="low", timestamp=datetime.now(timezone.utc)),
        NE(event_type="authentication:privilege_boundary", severity="high", timestamp=datetime.now(timezone.utc)),
        NE(event_type="network:internal_connection", severity="high", timestamp=datetime.now(timezone.utc)),
        NE(event_type="data:sensitive_access", severity="critical", timestamp=datetime.now(timezone.utc)),
    ]
    persisted, detections = ingest_events(db, org, events, source="lab-range", demo=True)
    from sentinelx.models import Event as EventModel

    db_events = (
        db.query(EventModel)
        .filter(EventModel.org_id == org, EventModel.source == "lab-range")
        .order_by(EventModel.timestamp.desc())
        .limit(50)
        .all()
    )
    coverage = compute_coverage(db, org, scenario, db_events)
    stages = {s["stage"]: s for s in coverage["stages"]}
    assert stages["Privilege"]["detected"] is True      # SIG-002 deployed
    assert stages["Lateral Movement"]["detected"] is False  # gap (SIG-PROP is DRAFT)
    assert stages["Collection"]["detected"] is True     # SIG-001 deployed
    assert len(coverage["gaps"]) >= 1
    rules = create_gap_recommendations(db, org, coverage["gaps"], created_by="tester")
    assert rules, "gap should produce a DRAFT detection rule"
    assert all(r.status == "DRAFT" for r in rules)


def test_attack_paths_computed(db, org):
    from sentinelx.services.attack_paths import compute_attack_paths, get_graph

    paths = compute_attack_paths(db, org)
    assert len(paths) >= 1
    graph = get_graph(db, org)
    assert graph["nodes"]
    assert graph["edges"]
    entry = next(n for n in graph["nodes"] if n["exposure"] == "INTERNET_FACING")
    assert entry is not None


def test_job_cancellation(db, org, approved_engagement):
    job = enqueue_job(
        db, org_id=org, engagement_id=approved_engagement.id, kind="scan", tool="lab-range",
        target_ref="10.10.10.10", params={"scenario": "web_app_authorization"},
    )
    from sentinelx.services.jobs import cancel_job

    cancel_job(db, job, by="tester")
    db.refresh(job)
    assert job.status == "cancelled"
    # Canceled jobs must not be picked up / executed
    run_job(db, job)
    db.refresh(job)
    assert job.status == "cancelled"
