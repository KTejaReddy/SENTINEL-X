"""Platform models: audit log, AI agents, policies, reports, notifications."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from ..db import Base, json_type
from .core import TimestampMixin, new_id


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    org_id: Mapped[str | None] = mapped_column(ForeignKey("organizations.id"), index=True, nullable=True)
    user_id: Mapped[str | None] = mapped_column(String(32), index=True, nullable=True)
    action: Mapped[str] = mapped_column(String(128), index=True)
    resource_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    resource_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    detail: Mapped[dict] = mapped_column(json_type(), default=dict)
    ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(255), nullable=True)
    outcome: Mapped[str] = mapped_column(String(16), default="success")  # success|denied|error
    request_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    hash_chain: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True, default=datetime.now)


class Agent(Base, TimestampMixin):
    __tablename__ = "agents"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    org_id: Mapped[str | None] = mapped_column(ForeignKey("organizations.id"), index=True, nullable=True)
    name: Mapped[str] = mapped_column(String(64), unique=True)
    role: Mapped[str] = mapped_column(String(32), default="specialist")  # orchestrator|specialist
    permissions: Mapped[list] = mapped_column(json_type(), default=list)
    tool_access: Mapped[list] = mapped_column(json_type(), default=list)
    scope: Mapped[dict] = mapped_column(json_type(), default=dict)
    input_schema: Mapped[dict] = mapped_column(json_type(), default=dict)
    output_schema: Mapped[dict] = mapped_column(json_type(), default=dict)
    enabled: Mapped[bool] = mapped_column(default=True)
    metadata_json: Mapped[dict] = mapped_column(json_type(), default=dict)


class AgentRun(Base, TimestampMixin):
    __tablename__ = "agent_runs"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    agent_id: Mapped[str | None] = mapped_column(ForeignKey("agents.id"), index=True, nullable=True)
    org_id: Mapped[str | None] = mapped_column(ForeignKey("organizations.id"), index=True, nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="completed")
    input: Mapped[dict] = mapped_column(json_type(), default=dict)
    output: Mapped[dict] = mapped_column(json_type(), default=dict)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    model: Mapped[str | None] = mapped_column(String(64), nullable=True)
    prompt_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Policy(Base, TimestampMixin):
    __tablename__ = "policies"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    org_id: Mapped[str | None] = mapped_column(ForeignKey("organizations.id"), index=True, nullable=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    kind: Mapped[str] = mapped_column(String(32), default="offensive")  # offensive|response|ai
    rules: Mapped[dict] = mapped_column(json_type(), default=dict)
    active: Mapped[bool] = mapped_column(default=True)


class Report(Base, TimestampMixin):
    __tablename__ = "reports"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    report_type: Mapped[str] = mapped_column(String(32), default="executive", index=True)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    status: Mapped[str] = mapped_column(String(16), default="generated")
    format: Mapped[str] = mapped_column(String(16), default="markdown")
    content: Mapped[dict] = mapped_column(json_type(), default=dict)
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    created_by: Mapped[str | None] = mapped_column(String(32), nullable=True)
    engagement_id: Mapped[str | None] = mapped_column(String(32), nullable=True)


class Notification(Base):
    __tablename__ = "notifications"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    user_id: Mapped[str | None] = mapped_column(String(32), index=True, nullable=True)
    kind: Mapped[str] = mapped_column(String(32), index=True)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    body: Mapped[str | None] = mapped_column(Text, nullable=True)
    link: Mapped[str | None] = mapped_column(String(512), nullable=True)
    read: Mapped[bool] = mapped_column(default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
