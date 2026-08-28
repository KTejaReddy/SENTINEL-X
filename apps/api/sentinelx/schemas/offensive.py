from __future__ import annotations

from datetime import date, datetime
from typing import Any, Optional

from pydantic import BaseModel, Field

from .core import ORMModel


class FindingCreate(BaseModel):
    asset_id: Optional[str] = None
    engagement_id: Optional[str] = None
    title: str = Field(min_length=3, max_length=512)
    description: Optional[str] = None
    severity: str = "MEDIUM"
    cvss: Optional[float] = Field(default=None, ge=0, le=10)
    cvss_vector: Optional[str] = None
    cve: Optional[str] = None
    cwe: Optional[str] = None
    category: Optional[str] = None
    source: str = "manual"
    endpoint: Optional[str] = None
    confidence: float = 0.5
    exploitability: str = "UNKNOWN"
    business_impact: Optional[str] = None
    remediation: Optional[str] = None
    metadata: dict[str, Any] = Field(default_factory=dict, alias="metadata_json")


class FindingUpdate(BaseModel):
    status: Optional[str] = None
    severity: Optional[str] = None
    owner: Optional[str] = None
    due_date: Optional[date] = None
    remediation: Optional[str] = None
    business_impact: Optional[str] = None
    exploitability: Optional[str] = None
    risk_accepted_reason: Optional[str] = None


class FindingOut(ORMModel):
    id: str
    org_id: str
    asset_id: Optional[str]
    engagement_id: Optional[str]
    title: str
    description: Optional[str]
    severity: str
    cvss: Optional[float]
    cvss_vector: Optional[str]
    cve: Optional[str]
    cwe: Optional[str]
    category: Optional[str]
    source: str
    endpoint: Optional[str]
    status: str
    confidence: float
    exploitability: str
    business_impact: Optional[str]
    remediation: Optional[str]
    due_date: Optional[date]
    owner: Optional[str]
    validated: bool
    attack_path_relevant: bool
    ai_triage: dict[str, Any]
    evidence_refs: list[Any]
    demo: bool
    metadata_json: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
    updated_at: datetime


class EvidenceCreate(BaseModel):
    finding_id: Optional[str] = None
    incident_id: Optional[str] = None
    engagement_id: Optional[str] = None
    kind: str = "TOOL_OUTPUT"
    data: dict[str, Any] = Field(default_factory=dict)
    tool: Optional[str] = None
    captured_at: Optional[datetime] = None


class EvidenceOut(ORMModel):
    id: str
    org_id: str
    finding_id: Optional[str]
    incident_id: Optional[str]
    engagement_id: Optional[str]
    kind: str
    content_hash: str
    storage_ref: Optional[str]
    data: dict[str, Any]
    tool: Optional[str]
    captured_at: Optional[datetime]
    demo: bool
    immutable: bool
    created_at: datetime


class RemediationCreate(BaseModel):
    finding_id: str
    owner: Optional[str] = None
    due_date: Optional[date] = None
    notes: Optional[str] = None


class RemediationOut(ORMModel):
    id: str
    finding_id: str
    status: str
    owner: Optional[str]
    due_date: Optional[date]
    notes: Optional[str]
    verification: dict[str, Any]


class RetestOut(ORMModel):
    id: str
    finding_id: str
    job_id: Optional[str]
    status: str
    before_result: dict[str, Any]
    after_result: dict[str, Any]
    evidence_ref: Optional[str]
    created_at: datetime


class AttackPathNodeOut(ORMModel):
    id: str
    ordinal: int
    asset_id: Optional[str]
    label: str
    role: str
    node_type: str
    evidence_refs: list[Any]
    detail: dict[str, Any]


class AttackPathOut(ORMModel):
    id: str
    org_id: str
    name: str
    description: Optional[str]
    entry_asset_id: Optional[str]
    target_asset_id: Optional[str]
    risk_score: float
    status: str
    stages: list[Any]
    metadata_json: dict[str, Any]
    created_at: datetime
    nodes: list[AttackPathNodeOut] = []
