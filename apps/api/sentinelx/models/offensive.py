"""Offensive security models: engagements, scope, jobs, findings, evidence."""
from __future__ import annotations

from datetime import date, datetime

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..db import Base, json_type
from .core import TimestampMixin, new_id

ENGAGEMENT_STATUSES = [
    "DRAFT", "PENDING_APPROVAL", "APPROVED", "RUNNING", "PAUSED", "COMPLETED", "CLOSED",
]
JOB_STATUSES = ["queued", "running", "paused", "cancelled", "failed", "completed"]
FINDING_STATUSES = [
    "NEW", "TRIAGED", "VALIDATING", "VALIDATED", "RISK_ACCEPTED",
    "REMEDIATION", "FIXED", "RETESTING", "VERIFIED", "CLOSED",
]


class Engagement(Base, TimestampMixin):
    __tablename__ = "engagements"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(24), default="DRAFT", index=True)
    start_date: Mapped[date | None] = mapped_column(nullable=True)
    end_date: Mapped[date | None] = mapped_column(nullable=True)
    # Policy config: rate limits, destructive testing, data handling, allowed tools
    config: Mapped[dict] = mapped_column(json_type(), default=dict)
    approved_by: Mapped[str | None] = mapped_column(String(32), nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_by: Mapped[str | None] = mapped_column(String(32), nullable=True)
    source: Mapped[str] = mapped_column(String(32), default="manual")

    scope_rules = relationship("ScopeRule", back_populates="engagement", cascade="all, delete-orphan")
    jobs = relationship("Job", back_populates="engagement")
    findings = relationship("Finding", back_populates="engagement")


class ScopeRule(Base, TimestampMixin):
    __tablename__ = "scope_rules"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    engagement_id: Mapped[str] = mapped_column(ForeignKey("engagements.id"), index=True)
    kind: Mapped[str] = mapped_column(String(16), default="INCLUDE")  # INCLUDE | EXCLUDE
    match_type: Mapped[str] = mapped_column(String(16), default="CIDR")  # CIDR|DOMAIN|HOSTNAME|IP|ASSET
    value: Mapped[str] = mapped_column(String(512), nullable=False)
    note: Mapped[str | None] = mapped_column(Text, nullable=True)

    engagement = relationship("Engagement", back_populates="scope_rules")


class Tool(Base):
    __tablename__ = "tools"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    category: Mapped[str] = mapped_column(String(32), default="scanner")
    installed: Mapped[bool] = mapped_column(default=False)
    version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    health: Mapped[str] = mapped_column(String(16), default="UNKNOWN")  # OK|NOT_INSTALLED|ERROR
    last_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    metadata_json: Mapped[dict] = mapped_column(json_type(), default=dict)


class Job(Base, TimestampMixin):
    __tablename__ = "jobs"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    engagement_id: Mapped[str | None] = mapped_column(ForeignKey("engagements.id"), index=True, nullable=True)
    kind: Mapped[str] = mapped_column(String(32), default="scan", index=True)
    # recon | scan | validate | retest | purple | exercise | ingest
    tool: Mapped[str] = mapped_column(String(64), default="lab-range")
    target_ref: Mapped[str | None] = mapped_column(String(128), nullable=True)  # asset id or raw target
    status: Mapped[str] = mapped_column(String(16), default="queued", index=True)
    progress: Mapped[int] = mapped_column(Integer, default=0)
    params: Mapped[dict] = mapped_column(json_type(), default=dict)
    result: Mapped[dict] = mapped_column(json_type(), default=dict)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    logs: Mapped[list] = mapped_column(json_type(), default=list)
    worker: Mapped[str | None] = mapped_column(String(64), nullable=True)
    retry_count: Mapped[int] = mapped_column(Integer, default=0)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    cancelled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_by: Mapped[str | None] = mapped_column(String(32), nullable=True)
    demo: Mapped[bool] = mapped_column(default=False)

    engagement = relationship("Engagement", back_populates="jobs")


class Scan(Base, TimestampMixin):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    engagement_id: Mapped[str | None] = mapped_column(ForeignKey("engagements.id"), nullable=True)
    job_id: Mapped[str | None] = mapped_column(ForeignKey("jobs.id"), nullable=True)
    tool: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(16), default="running")
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    summary: Mapped[dict] = mapped_column(json_type(), default=dict)


class Finding(Base, TimestampMixin):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    asset_id: Mapped[str | None] = mapped_column(ForeignKey("assets.id"), index=True, nullable=True)
    engagement_id: Mapped[str | None] = mapped_column(ForeignKey("engagements.id"), index=True, nullable=True)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(String(16), default="MEDIUM", index=True)
    cvss: Mapped[float | None] = mapped_column(Float, nullable=True)
    cvss_vector: Mapped[str | None] = mapped_column(String(128), nullable=True)
    cve: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    cwe: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    category: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    source: Mapped[str] = mapped_column(String(64), default="manual", index=True)
    endpoint: Mapped[str | None] = mapped_column(String(512), nullable=True)
    status: Mapped[str] = mapped_column(String(24), default="NEW", index=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    exploitability: Mapped[str] = mapped_column(String(16), default="UNKNOWN")
    business_impact: Mapped[str | None] = mapped_column(String(512), nullable=True)
    remediation: Mapped[str | None] = mapped_column(Text, nullable=True)
    due_date: Mapped[date | None] = mapped_column(nullable=True)
    owner: Mapped[str | None] = mapped_column(String(255), nullable=True)
    dedup_key: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    validated: Mapped[bool] = mapped_column(default=False)
    attack_path_relevant: Mapped[bool] = mapped_column(default=False)
    metadata_json: Mapped[dict] = mapped_column(json_type(), default=dict)
    evidence_refs: Mapped[list] = mapped_column(json_type(), default=list)
    ai_triage: Mapped[dict] = mapped_column(json_type(), default=dict)
    demo: Mapped[bool] = mapped_column(default=False)

    asset = relationship("Asset", back_populates="findings")
    engagement = relationship("Engagement", back_populates="findings")
    evidence = relationship("Evidence", back_populates="finding")
    retests = relationship("Retest", back_populates="finding")


class Evidence(Base, TimestampMixin):
    __tablename__ = "evidence"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    engagement_id: Mapped[str | None] = mapped_column(ForeignKey("engagements.id"), nullable=True)
    finding_id: Mapped[str | None] = mapped_column(ForeignKey("findings.id"), index=True, nullable=True)
    incident_id: Mapped[str | None] = mapped_column(ForeignKey("incidents.id"), index=True, nullable=True)
    kind: Mapped[str] = mapped_column(String(32), default="TOOL_OUTPUT")  # SCREENSHOT|HTTP|LOG|TOOL_OUTPUT|TEST_RESULT|REPORT|LAB_REPLAY
    content_hash: Mapped[str] = mapped_column(String(64), index=True)
    storage_ref: Mapped[str | None] = mapped_column(String(512), nullable=True)
    data: Mapped[dict] = mapped_column(json_type(), default=dict)
    tool: Mapped[str | None] = mapped_column(String(64), nullable=True)
    captured_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    demo: Mapped[bool] = mapped_column(default=False)
    immutable: Mapped[bool] = mapped_column(default=True)
    created_by: Mapped[str | None] = mapped_column(String(32), nullable=True)

    finding = relationship("Finding", back_populates="evidence")


class Remediation(Base, TimestampMixin):
    __tablename__ = "remediations"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    finding_id: Mapped[str] = mapped_column(ForeignKey("findings.id"), index=True)
    status: Mapped[str] = mapped_column(String(24), default="OPEN")  # OPEN|IN_PROGRESS|VERIFIED|CLOSED
    owner: Mapped[str | None] = mapped_column(String(255), nullable=True)
    due_date: Mapped[date | None] = mapped_column(nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    verification: Mapped[dict] = mapped_column(json_type(), default=dict)


class Retest(Base, TimestampMixin):
    __tablename__ = "retests"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    finding_id: Mapped[str] = mapped_column(ForeignKey("findings.id"), index=True)
    job_id: Mapped[str | None] = mapped_column(ForeignKey("jobs.id"), nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="PENDING")  # PENDING|PASSED|FAILED|ERROR
    before_result: Mapped[dict] = mapped_column(json_type(), default=dict)
    after_result: Mapped[dict] = mapped_column(json_type(), default=dict)
    evidence_ref: Mapped[str | None] = mapped_column(String(32), nullable=True)
    created_by: Mapped[str | None] = mapped_column(String(32), nullable=True)

    finding = relationship("Finding", back_populates="retests")
