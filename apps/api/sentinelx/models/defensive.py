"""Defensive security models: events, detection rules, incidents, playbooks."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..db import Base, json_type
from .core import TimestampMixin, new_id

INCIDENT_STATUSES = ["OPEN", "INVESTIGATING", "CONTAINED", "ERADICATION", "RECOVERY", "RESOLVED", "CLOSED"]
RISK_LEVELS = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


class Event(Base, TimestampMixin):
    """Normalized security telemetry event (common schema)."""
    __tablename__ = "events"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    event_id: Mapped[str] = mapped_column(String(64), index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    source: Mapped[str] = mapped_column(String(64), index=True)  # suricata|zeek|wazuh|sysmon|lab-range|...
    asset_id: Mapped[str | None] = mapped_column(ForeignKey("assets.id"), index=True, nullable=True)
    user_id: Mapped[str | None] = mapped_column(String(64), index=True, nullable=True)
    event_type: Mapped[str] = mapped_column(String(64), index=True)
    severity: Mapped[str] = mapped_column(String(16), default="low", index=True)
    metadata_json: Mapped[dict] = mapped_column("metadata", json_type(), default=dict)
    dedup_hash: Mapped[str | None] = mapped_column(String(64), index=True, nullable=True)
    demo: Mapped[bool] = mapped_column(default=False)


class DetectionRule(Base, TimestampMixin):
    __tablename__ = "detection_rules"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    rule_id: Mapped[str] = mapped_column(String(64), index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    source: Mapped[str] = mapped_column(String(32), default="CUSTOM")  # SIGMA|SURICATA|WAZUH|CUSTOM
    version: Mapped[int] = mapped_column(default=1)
    severity: Mapped[str] = mapped_column(String(16), default="medium")
    mitre: Mapped[list] = mapped_column(json_type(), default=list)
    # logic: {"type": "signature"|"threshold"|"correlation", "match": {...}, "window_seconds": 300, "threshold": 5, "sequence": [...]}
    logic: Mapped[dict] = mapped_column(json_type(), default=dict)
    status: Mapped[str] = mapped_column(String(16), default="DRAFT", index=True)  # DRAFT|TEST|DEPLOYED|DISABLED
    false_positive_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    test_cases: Mapped[list] = mapped_column(json_type(), default=list)
    regression_test: Mapped[bool] = mapped_column(default=False)
    created_by: Mapped[str | None] = mapped_column(String(32), nullable=True)


class Incident(Base, TimestampMixin):
    __tablename__ = "incidents"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), default="medium", index=True)
    status: Mapped[str] = mapped_column(String(24), default="OPEN", index=True)
    assignee_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    detection_sources: Mapped[list] = mapped_column(json_type(), default=list)
    attack_techniques: Mapped[list] = mapped_column(json_type(), default=list)
    affected_assets: Mapped[list] = mapped_column(json_type(), default=list)
    affected_users: Mapped[list] = mapped_column(json_type(), default=list)
    related_findings: Mapped[list] = mapped_column(json_type(), default=list)
    ai_analysis: Mapped[dict] = mapped_column(json_type(), default=dict)
    root_cause: Mapped[str | None] = mapped_column(Text, nullable=True)
    remediation_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    demo: Mapped[bool] = mapped_column(default=False)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    timeline = relationship("IncidentTimelineEntry", back_populates="incident", cascade="all, delete-orphan")


class IncidentTimelineEntry(Base):
    __tablename__ = "incident_timeline_entries"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id"), index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    event_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    source: Mapped[str | None] = mapped_column(String(64), nullable=True)
    kind: Mapped[str] = mapped_column(String(24), default="OBSERVATION")  # OBSERVATION|DETECTION|RESPONSE|RECOVERY
    message: Mapped[str] = mapped_column(Text, nullable=False)
    evidence_refs: Mapped[list] = mapped_column(json_type(), default=list)

    incident = relationship("Incident", back_populates="timeline")


class Playbook(Base, TimestampMixin):
    __tablename__ = "playbooks"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="ACTIVE")
    triggers: Mapped[dict] = mapped_column(json_type(), default=dict)

    actions = relationship("ResponseAction", back_populates="playbook", cascade="all, delete-orphan")


class ResponseAction(Base, TimestampMixin):
    __tablename__ = "response_actions"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    playbook_id: Mapped[str | None] = mapped_column(ForeignKey("playbooks.id"), index=True, nullable=True)
    incident_id: Mapped[str | None] = mapped_column(ForeignKey("incidents.id"), index=True, nullable=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    risk_level: Mapped[str] = mapped_column(String(16), default="MEDIUM", index=True)
    # action_type: CREATE_TICKET|ENABLE_MONITORING|DISABLE_ACCOUNT|REVOKE_SESSION|
    #              ISOLATE_ENDPOINT|BLOCK_NETWORK|CREDENTIAL_ROTATION|SERVICE_ISOLATION|COLLECT_EVIDENCE
    action_type: Mapped[str] = mapped_column(String(32), nullable=False)
    target: Mapped[dict] = mapped_column(json_type(), default=dict)
    requires_approval: Mapped[bool] = mapped_column(default=True)
    status: Mapped[str] = mapped_column(String(24), default="PENDING_APPROVAL", index=True)
    approved_by: Mapped[str | None] = mapped_column(String(32), nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    executed_by: Mapped[str | None] = mapped_column(String(32), nullable=True)
    executed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    result: Mapped[dict] = mapped_column(json_type(), default=dict)
    demo: Mapped[bool] = mapped_column(default=False)

    playbook = relationship("Playbook", back_populates="actions")
