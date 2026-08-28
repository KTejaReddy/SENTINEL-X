"""Asynchronous job system.

Security operations run as jobs on workers. The queue is database-backed so
multiple workers can run against the same store without Redis; Redis can be
added later as a transport. Workers claim jobs with an atomic status update.

API → Job(queued) → Worker(claim) → ToolAdapter (scope+policy gated) → result
   → DB → event → WebSocket → UI
"""
from __future__ import annotations

import asyncio
import logging
import time
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy.orm import Session

from ..db import SessionLocal
from ..integrations import get_registry
from ..integrations.base import AdapterError, ToolNotInstalled
from ..models import Asset, Engagement, Job, Scan
from ..realtime import hub
from .policy_engine import evaluate_policy

logger = logging.getLogger(__name__)

MAX_RETRIES = 2
RETRY_BACKOFF = 5  # seconds base


def enqueue_job(
    db: Session,
    *,
    org_id: str,
    engagement_id: str,
    kind: str,
    tool: str,
    target_ref: Optional[str] = None,
    params: Optional[dict[str, Any]] = None,
    created_by: Optional[str] = None,
    demo: bool = False,
) -> Job:
    job = Job(
        org_id=org_id,
        engagement_id=engagement_id,
        kind=kind,
        tool=tool,
        target_ref=target_ref,
        params=params or {},
        status="queued",
        created_by=created_by,
        demo=demo,
        logs=[{"ts": datetime.now(timezone.utc).isoformat(), "level": "info", "msg": "queued"}],
    )
    db.add(job)
    db.commit()
    db.refresh(job)
    _emit(db, job, "job_queued")
    return job


def cancel_job(db: Session, job: Job, by: Optional[str] = None) -> Job:
    if job.status in {"completed", "cancelled", "failed"}:
        return job
    job.status = "cancelled"
    job.cancelled_at = datetime.now(timezone.utc)
    job.logs = job.logs + [{"ts": datetime.now(timezone.utc).isoformat(), "level": "warn", "msg": f"cancelled by {by or 'unknown'}"}]
    db.commit()
    _emit(db, job, "job_cancelled")
    return job


def pause_job(db: Session, job: Job) -> Job:
    if job.status == "queued":
        job.status = "paused"
        db.commit()
        _emit(db, job, "job_paused")
    return job


def resume_job(db: Session, job: Job) -> Job:
    if job.status == "paused":
        job.status = "queued"
        db.commit()
        _emit(db, job, "job_resumed")
    return job


def retry_job(db: Session, job: Job, by: Optional[str] = None) -> Job:
    if job.status in {"failed", "cancelled", "completed"}:
        job.status = "queued"
        job.error = None
        job.retry_count = job.retry_count + 1
        db.commit()
        _emit(db, job, "job_retried")
    return job


def _emit(db: Session, job: Job, event_type: str) -> None:
    hub.publish_sync(
        job.org_id,
        event_type,
        {"job_id": job.id, "status": job.status, "kind": job.kind, "tool": job.tool, "progress": job.progress},
    )


def _append_log(job: Job, level: str, msg: str) -> None:
    job.logs = (job.logs or []) + [
        {"ts": datetime.now(timezone.utc).isoformat(), "level": level, "msg": msg}
    ]


def run_job(db: Session, job: Job) -> None:
    """Execute a claimed job. Runs the full gate: scope → policy → adapter."""
    if job.status not in {"queued", "running"} or job.cancelled_at is not None:
        return
    engagement = db.get(Engagement, job.engagement_id)
    if engagement is None:
        job.status = "failed"
        job.error = "Engagement not found"
        db.commit()
        return

    asset = None
    target_ref = job.target_ref
    if target_ref:
        asset = db.get(Asset, target_ref)
        if asset is not None and asset.org_id != job.org_id:
            job.status = "failed"
            job.error = "Target asset belongs to another organization"
            db.commit()
            return
        if asset is None:
            asset = (
                db.query(Asset)
                .filter(Asset.org_id == job.org_id, Asset.ip_address == target_ref)
                .first()
            )

    action = {"recon": "recon", "scan": "scan", "validate": "validate", "retest": "retest", "ingest": "scan", "purple": "scan"}.get(job.kind, "scan")

    policy = evaluate_policy(
        db,
        engagement=engagement,
        target_ref=target_ref,
        tool=job.tool,
        action=action,
        asset_id=asset.id if asset else None,
        asset=asset,
        actor="worker",
    )
    if not policy.allowed:
        job.status = "failed"
        job.error = f"Policy denied: {policy.reason}"
        _append_log(job, "error", f"POLICY DENIED: {policy.reason}")
        db.commit()
        return

    adapter = get_registry().get(job.tool)
    job.started_at = datetime.now(timezone.utc)
    job.worker = "worker-local"
    job.status = "running"
    job.progress = 10
    _append_log(job, "info", f"policy OK: {policy.reason}")
    _append_log(job, "info", f"starting {adapter.name} against {target_ref or '(engagement-wide)'}")
    db.commit()
    _emit(db, job, "job_started")

    scan = Scan(
        org_id=job.org_id,
        engagement_id=job.engagement_id,
        job_id=job.id,
        tool=job.tool,
        status="running",
        started_at=job.started_at,
    )
    db.add(scan)
    db.commit()

    try:
        result = adapter.run(db, engagement, target_ref or "", job.params, asset=asset)
        job.progress = 70
        db.commit()

        from .findings import ingest_normalized
        from .events import ingest_events
        from .assets import upsert_assets_and_services

        # Persist normalized output
        if result.get("assets"):
            upsert_assets_and_services(db, job.org_id, result["assets"], result.get("services", []), source=adapter.name)
        if result.get("events"):
            ingest_events(db, job.org_id, result["events"], source=adapter.name, demo=job.demo or bool(result.get("meta", {}).get("demo")))
        findings_created, findings_updated, linked = 0, 0, []
        if result.get("findings"):
            from .evidence import store_evidence

            # Link adapter findings to the engagement target asset so they feed
            # the attack-path engine and per-asset views.
            if asset is not None and asset.ip_address:
                for nf in result["findings"]:
                    if not nf.asset_ip and not nf.asset_name:
                        nf.asset_ip = asset.ip_address

            findings_created, findings_updated, linked = ingest_normalized(
                db, job.org_id, engagement.id, result["findings"],
                tool=adapter.name,
                demo=job.demo or bool(result.get("meta", {}).get("demo")),
            )
            # Link evidence to the newly created findings
            if linked:
                for finding_id, ev_data in linked:
                    store_evidence(
                        db, org_id=job.org_id, engagement_id=engagement.id,
                        finding_id=finding_id, kind="TOOL_OUTPUT",
                        data=ev_data, tool=adapter.name,
                        demo=job.demo or bool(result.get("meta", {}).get("demo")),
                        captured_at=datetime.now(timezone.utc),
                        created_by=job.created_by,
                    )

        # Validate jobs: promote the targeted finding to VALIDATED with evidence
        if job.kind == "validate" and job.params.get("finding_id"):
            from .findings import validate_finding
            from ..models import Finding as FindingModel

            target = db.get(FindingModel, job.params["finding_id"])
            if target is not None and target.org_id == job.org_id:
                validate_finding(
                    db, target,
                    evidence_data={
                        "type": "controlled_validation",
                        "tool": adapter.name,
                        "scenario": job.params.get("scenario", "web_app_authorization"),
                        "label": "CONTROLLED LAB",
                        "target": target_ref,
                    },
                    tool=adapter.name,
                )

        # Retest jobs: compare before/after and update the finding
        retest_outcome = None
        if job.kind == "retest" and job.params.get("finding_id"):
            from .findings import dedup_key as finding_dedup_key
            from .retest import finalize_retest

            meta = result.get("meta", {}) or {}
            inconclusive = None
            if meta.get("target_unreachable"):
                inconclusive = "scan target unreachable — no probes executed"
            elif meta.get("probes_executed", 0) == 0:
                inconclusive = "scan executed no probes (check target configuration)"

            # Precision: the retest of THIS finding only PASSES when its own
            # dedup key is not re-reported by the scan (other findings in the
            # same scan are irrelevant).
            target_dedup = job.params.get("dedup_key")
            target_re_reported = False
            if target_dedup:
                for nf in result.get("findings", []):
                    nf_asset_id = None
                    if nf.asset_ip:
                        nf_asset_id = (
                            db.query(Asset)
                            .filter(Asset.org_id == job.org_id, Asset.ip_address == nf.asset_ip)
                            .first()
                        )
                        nf_asset_id = nf_asset_id.id if nf_asset_id else None
                    elif nf.asset_name:
                        nf_asset_id = (
                            db.query(Asset)
                            .filter(Asset.org_id == job.org_id, Asset.name == nf.asset_name)
                            .first()
                        )
                        nf_asset_id = nf_asset_id.id if nf_asset_id else None
                    if finding_dedup_key(job.org_id, nf_asset_id, nf.endpoint, nf.cve, nf.cwe, nf.category) == target_dedup:
                        target_re_reported = True
                        break

            retest_outcome = finalize_retest(
                db, job, job.params["finding_id"], findings_created, findings_updated,
                evidence_data={"tool_output": meta},
                inconclusive_reason=inconclusive,
                target_re_reported=target_re_reported,
            )

        job.progress = 90
        job.result = {
            "assets": len(result.get("assets", [])),
            "services": len(result.get("services", [])),
            "findings_created": findings_created,
            "findings_updated": findings_updated,
            "events": len(result.get("events", [])),
            "meta": result.get("meta", {}),
            "retest": {"status": retest_outcome.status} if retest_outcome else None,
            "policy": {"allowed": True, "reason": policy.reason},
        }
        scan.status = "completed"
        scan.finished_at = datetime.now(timezone.utc)
        scan.summary = job.result
        _append_log(job, "info", f"completed: {job.result}")
        job.status = "completed"
        job.progress = 100
        job.finished_at = datetime.now(timezone.utc)
        db.commit()
        _emit(db, job, "job_completed")
    except ToolNotInstalled as exc:
        job.status = "failed"
        job.error = str(exc)
        _append_log(job, "warn", f"tool unavailable: {exc}")
        scan.status = "failed"
        scan.finished_at = datetime.now(timezone.utc)
        db.commit()
        _emit(db, job, "job_failed")
    except AdapterError as exc:
        job.status = "failed"
        job.error = str(exc)
        _append_log(job, "error", f"adapter error: {exc}")
        scan.status = "failed"
        scan.finished_at = datetime.now(timezone.utc)
        db.commit()
        _emit(db, job, "job_failed")
    except Exception as exc:  # noqa: BLE001 — job isolation
        logger.exception("job %s crashed", job.id)
        job.status = "failed"
        job.error = f"{type(exc).__name__}: {exc}"
        _append_log(job, "error", job.error)
        scan.status = "failed"
        scan.finished_at = datetime.now(timezone.utc)
        db.commit()
        _emit(db, job, "job_failed")


def _claim_next(db: Session) -> Optional[Job]:
    job = (
        db.query(Job)
        .filter(Job.status == "queued")
        .order_by(Job.created_at.asc())
        .first()
    )
    if job is None:
        return None
    updated = (
        db.query(Job)
        .filter(Job.id == job.id, Job.status == "queued")
        .update({"status": "running", "worker": "worker-local"})
    )
    db.commit()
    if updated != 1:
        return None
    db.refresh(job)
    return job


async def worker_loop(stop_event: Optional[asyncio.Event] = None, interval: float = 2.0) -> None:
    """Polling worker. Runs as a background task in the API process and can also
    be launched standalone (`python -m sentinelx.workers`) for scale-out."""
    logger.info("worker loop started")
    while True:
        if stop_event is not None and stop_event.is_set():
            logger.info("worker loop stopping")
            return
        db = SessionLocal()
        try:
            job = _claim_next(db)
            if job is not None:
                run_job(db, job)
        except Exception:  # noqa: BLE001
            logger.exception("worker iteration failed")
        finally:
            db.close()
        await asyncio.sleep(interval)
