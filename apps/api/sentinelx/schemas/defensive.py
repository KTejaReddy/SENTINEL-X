from __future__ import annotations

from datetime import datetime
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field

from .core import ORMModel


class EventCreate(BaseModel):
    event_id: str
    timestamp: datetime
    source: str
    asset_id: Optional[str] = None
    user_id: Optional[str] = None
    event_type: str
    severity: str = "low"
    metadata: dict[str, Any] = Field(default_factory=dict)


class EventOut(ORMModel):
    id: str
    org_id: str
    event_id: str
    timestamp: datetime
    source: str
    asset_id: Optional[str]
    user_id: Optional[str]
    event_type: str
    severity: str
    metadata_json: dict[str, Any]
    demo: bool
    created_at: datetime


class DetectionRuleCreate(BaseModel):
    rule_id: str
    name: str
    description: Optional[str] = None
    source: str = "CUSTOM"
    severity: str = "medium"
    mitre: list[str] = Field(default_factory=list)
    logic: dict[str, Any]
    status: str = "DRAFT"
    false_positive_notes: Optional[str] = None
    test_cases: list[Any] = Field(default_factory=list)


class DetectionRuleOut(ORMModel):
    id: str
    org_id: str
    rule_id: str
    name: str
    description: Optional[str]
    source: str
    version: int
    severity: str
    mitre: list[Any]
    logic: dict[str, Any]
    status: str
    false_positive_notes: Optional[str]
    test_cases: list[Any]
    regression_test: bool
    created_at: datetime


class IncidentCreate(BaseModel):
    title: str = Field(min_length=3, max_length=512)
    severity: str = "medium"
    status: str = "OPEN"
    description: Optional[str] = None
    assignee_id: Optional[str] = None
    detection_sources: list[str] = Field(default_factory=list)
    attack_techniques: list[str] = Field(default_factory=list)
    affected_assets: list[str] = Field(default_factory=list)
    affected_users: list[str] = Field(default_factory=list)
    related_findings: list[str] = Field(default_factory=list)


class IncidentUpdate(BaseModel):
    status: Optional[str] = None
    severity: Optional[str] = None
    assignee_id: Optional[str] = None
    description: Optional[str] = None
    root_cause: Optional[str] = None
    remediation_notes: Optional[str] = None


class IncidentOut(ORMModel):
    id: str
    org_id: str
    title: str
    severity: str
    status: str
    assignee_id: Optional[str]
    description: Optional[str]
    detection_sources: list[Any]
    attack_techniques: list[Any]
    affected_assets: list[Any]
    affected_users: list[Any]
    related_findings: list[Any]
    ai_analysis: dict[str, Any]
    root_cause: Optional[str]
    remediation_notes: Optional[str]
    demo: bool
    created_at: datetime
    updated_at: datetime
    closed_at: Optional[datetime]


class TimelineEntryOut(ORMModel):
    id: str
    incident_id: str
    timestamp: datetime
    event_id: Optional[str]
    source: Optional[str]
    kind: str
    message: str
    evidence_refs: list[Any]


class PlaybookCreate(BaseModel):
    name: str
    description: Optional[str] = None
    triggers: dict[str, Any] = Field(default_factory=dict)


class PlaybookOut(ORMModel):
    id: str
    org_id: str
    name: str
    description: Optional[str]
    status: str
    triggers: dict[str, Any]
    created_at: datetime
    actions: list["ResponseActionOut"] = []


class ResponseActionCreate(BaseModel):
    playbook_id: Optional[str] = None
    incident_id: Optional[str] = None
    name: str
    risk_level: str = "MEDIUM"
    action_type: str
    target: dict[str, Any] = Field(default_factory=dict)
    requires_approval: bool = True


class ResponseActionOut(ORMModel):
    id: str
    org_id: str
    playbook_id: Optional[str]
    incident_id: Optional[str]
    name: str
    risk_level: str
    action_type: str
    target: dict[str, Any]
    requires_approval: bool
    status: str
    approved_by: Optional[str]
    approved_at: Optional[datetime]
    executed_by: Optional[str]
    executed_at: Optional[datetime]
    result: dict[str, Any]
    demo: bool


class ApprovalRequest(BaseModel):
    approve: bool = True
    note: Optional[str] = None


# ---------- AI ----------
class AITriageRequest(BaseModel):
    finding_id: str


class AITriageResponse(BaseModel):
    classification: str = "candidate"
    severity: str = "MEDIUM"
    confidence: float = Field(ge=0, le=1)
    asset_criticality: str = "MEDIUM"
    business_risk: str = "MEDIUM"
    likely_attack_path: bool = False
    evidence_required: list[str] = Field(default_factory=list)
    recommended_validation: str = ""
    remediation: str = ""
    finding_id: str = ""


class AIIncidentRequest(BaseModel):
    incident_id: str


class AIIncidentAnalysis(BaseModel):
    summary: str = ""
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    affected_assets: list[str] = Field(default_factory=list)
    affected_identities: list[str] = Field(default_factory=list)
    timeline: list[dict[str, Any]] = Field(default_factory=list)
    attack_stage: str = "unknown"
    possible_root_cause: str = ""
    confidence: float = Field(ge=0, le=1, default=0.5)
    facts: list[str] = Field(default_factory=list)
    inferences: list[str] = Field(default_factory=list)
    hypotheses: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)


class AIActionRequest(BaseModel):
    action: str
    target_id: str
    objective: str = ""
    confidence: float = Field(default=0.5, ge=0, le=1)
    requires_approval: bool = True
    engagement_id: Optional[str] = None


class AIActionResponse(BaseModel):
    action: str
    target_id: str
    objective: str
    confidence: float
    requires_approval: bool
    allowed: bool = False
    reason: str = ""


class AICopilotRequest(BaseModel):
    question: str = Field(min_length=3, max_length=2000)


class AICopilotResponse(BaseModel):
    answer: str = ""
    citations: list[dict[str, Any]] = Field(default_factory=list)
    insufficient_evidence: list[str] = Field(default_factory=list)
    provider: str = "local"
    model: str = ""


# ---------- Purple ----------
class PurpleExerciseRequest(BaseModel):
    engagement_id: str
    scenario: str = "web_app_authorization"


class PurpleExerciseResult(BaseModel):
    exercise_id: str
    scenario: str
    stages: list[dict[str, Any]] = Field(default_factory=list)
    coverage: dict[str, Any] = Field(default_factory=dict)
    gaps: list[dict[str, Any]] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    incident_id: Optional[str] = None
    demo: bool = True


class PurpleCoverageOut(BaseModel):
    coverage: dict[str, Any] = Field(default_factory=dict)
    gaps: list[dict[str, Any]] = Field(default_factory=list)
    retest_status: dict[str, Any] = Field(default_factory=dict)
