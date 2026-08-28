"""Security retesting.

A retest re-runs the relevant assessment against the same finding. If the
finding is no longer reported, the retest PASSES and the finding moves to
VERIFIED. If it is re-reported, the retest FAILS (security regression detected).
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from ..models import Finding, Job, Retest
from .findings import dedup_key


def enqueue_retest(db: Session, finding: Finding, tool: str, engagement_id: str, created_by: str | None = None, extra_params: dict[str, Any] | None = None) -> Job:
    job = Job(
        org_id=finding.org_id,
        engagement_id=engagement_id,
        kind="retest",
        tool=tool,
        target_ref=finding.asset_id or finding.endpoint,
        params={
            "finding_id": finding.id,
            "dedup_key": finding.dedup_key,
            "endpoint": finding.endpoint,
            "scenario": (finding.metadata_json or {}).get("scenario", "web_app_authorization"),
            **(extra_params or {}),
        },
        status="queued",
        created_by=created_by,
        demo=finding.demo,
    )
    db.add(job)
    db.commit()
    db.refresh(job)
    return job


def finalize_retest(
    db: Session,
    job: Job,
    finding_id: str,
    findings_created: int,
    findings_updated: int,
    evidence_data: dict[str, Any] | None = None,
    inconclusive_reason: str | None = None,
    target_re_reported: bool | None = None,
) -> Retest:
    """Evaluate retest outcome after the adapter finished.

    A PASS means the finding's own dedup key was NOT re-reported by the
    retest scan AND the scan was conclusive (target reachable). A scan that
    ran no probes is INCONCLUSIVE — never reported as a pass (no false
    success). When `target_re_reported` is None (older callers) the coarse
    global counts are used.
    """
    finding = db.get(Finding, finding_id)
    if finding is None:
        return None  # type: ignore[return-value]

    from .evidence import store_evidence

    # A PASS means the finding's dedup key was NOT re-reported by the retest scan.
    re_reported = findings_created > 0 or findings_updated > 0 if target_re_reported is None else target_re_reported
    if inconclusive_reason:
        status = "FAILED"
        after_note = f"INCONCLUSIVE: {inconclusive_reason}"
    elif re_reported:
        status = "FAILED"
        after_note = "finding re-reported by retest scan (security regression)"
    else:
        status = "PASSED"
        after_note = "finding not re-reported by retest scan"

    evidence = store_evidence(
        db,
        org_id=finding.org_id,
        finding_id=finding.id,
        engagement_id=job.engagement_id,
        kind="TEST_RESULT",
        data={
            ** (evidence_data or {}),
            "retest_status": status,
            "tool": job.tool,
            "label": "RETEST",
        },
        tool=job.tool,
        demo=finding.demo,
        created_by=job.created_by,
    )

    retest = Retest(
        org_id=finding.org_id,
        finding_id=finding.id,
        job_id=job.id,
        status=status,
        before_result={"status": finding.status, "validated": finding.validated},
        after_result={"reported_again": re_reported, "findings_created": findings_created, "findings_updated": findings_updated, "note": after_note},
        evidence_ref=evidence.id,
        created_by=job.created_by,
    )
    db.add(retest)
    if status == "PASSED":
        finding.status = "VERIFIED"
        finding.metadata_json = {**(finding.metadata_json or {}), "retest_passed_at": datetime.now(timezone.utc).isoformat()}
    else:
        # SECURITY REGRESSION DETECTED
        finding.status = "VALIDATING"
        finding.validated = True
        finding.metadata_json = {
            **(finding.metadata_json or {}),
            "regression": True,
            "regression_detected_at": datetime.now(timezone.utc).isoformat(),
        }
    db.commit()
    db.refresh(retest)
    return retest
