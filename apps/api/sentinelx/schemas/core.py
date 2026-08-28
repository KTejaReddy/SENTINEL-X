from __future__ import annotations

from datetime import date, datetime
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, EmailStr, Field

from ..models.assets import ASSET_TYPES
from ..models.offensive import ENGAGEMENT_STATUSES, JOB_STATUSES


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


# ---------- Auth ----------
class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=200)


class RefreshRequest(BaseModel):
    refresh_token: str


class LoginResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    user: "UserOut"


# ---------- Organizations / Users ----------
class OrganizationCreate(BaseModel):
    name: str = Field(min_length=2, max_length=255)
    slug: str = Field(min_length=2, max_length=64, pattern=r"^[a-z0-9-]+$")
    plan: str = "enterprise"


class OrganizationOut(ORMModel):
    id: str
    name: str
    slug: str
    plan: str
    is_demo: bool


class UserCreate(BaseModel):
    email: EmailStr
    name: str = Field(min_length=1, max_length=255)
    password: str = Field(min_length=8, max_length=200)
    role: str = "VIEWER"
    org_id: Optional[str] = None


class UserOut(ORMModel):
    id: str
    org_id: Optional[str]
    email: str
    name: str
    role: str
    status: str
    mfa_enabled: bool
    last_login_at: Optional[datetime] = None
    created_at: datetime


# ---------- Assets ----------
class AssetCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    asset_type: str = Field(default="HOST", pattern="|".join(ASSET_TYPES))
    owner: Optional[str] = None
    environment: Optional[str] = None
    criticality: str = "MEDIUM"
    zone: Optional[str] = None
    ip_address: Optional[str] = None
    dns_name: Optional[str] = None
    technology: Optional[str] = None
    os: Optional[str] = None
    exposure: str = "UNKNOWN"
    auth_required: bool = True
    managed: bool = True
    metadata: dict[str, Any] = Field(default_factory=dict, alias="metadata_json")


class AssetUpdate(BaseModel):
    name: Optional[str] = None
    owner: Optional[str] = None
    environment: Optional[str] = None
    criticality: Optional[str] = None
    zone: Optional[str] = None
    ip_address: Optional[str] = None
    dns_name: Optional[str] = None
    technology: Optional[str] = None
    os: Optional[str] = None
    exposure: Optional[str] = None
    managed: Optional[bool] = None
    status: Optional[str] = None


class AssetOut(ORMModel):
    id: str
    org_id: str
    name: str
    asset_type: str
    owner: Optional[str]
    environment: Optional[str]
    criticality: str
    zone: Optional[str]
    ip_address: Optional[str]
    dns_name: Optional[str]
    technology: Optional[str]
    os: Optional[str]
    exposure: str
    auth_required: bool
    status: str
    managed: bool
    last_seen: Optional[datetime]
    source: str
    metadata_json: dict[str, Any]
    created_at: datetime


class ServiceOut(ORMModel):
    id: str
    asset_id: str
    name: str
    port: Optional[int]
    protocol: Optional[str]
    version: Optional[str]
    technology: Optional[str]
    state: str


# ---------- Engagements ----------
class ScopeRuleCreate(BaseModel):
    kind: str = "INCLUDE"
    match_type: str = "CIDR"
    value: str
    note: Optional[str] = None


class ScopeRuleOut(ORMModel):
    id: str
    engagement_id: str
    kind: str
    match_type: str
    value: str
    note: Optional[str]


class EngagementCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    description: Optional[str] = None
    start_date: Optional[date] = None
    end_date: Optional[date] = None
    config: dict[str, Any] = Field(default_factory=lambda: {
        "allowed_tools": [],
        "max_request_rate": 10,
        "destructive_testing": False,
        "data_handling": "no_pii",
    })
    scope_rules: list[ScopeRuleCreate] = Field(default_factory=list)


class EngagementOut(ORMModel):
    id: str
    org_id: str
    name: str
    description: Optional[str]
    status: str
    start_date: Optional[date]
    end_date: Optional[date]
    config: dict[str, Any]
    approved_by: Optional[str]
    approved_at: Optional[datetime]
    created_by: Optional[str]
    source: str
    created_at: datetime
    scope_rules: list[ScopeRuleOut] = []


# ---------- Jobs / Tools ----------
class JobCreate(BaseModel):
    engagement_id: str
    kind: str = "scan"
    tool: str = "lab-range"
    target_ref: Optional[str] = None
    params: dict[str, Any] = Field(default_factory=dict)


class JobOut(ORMModel):
    id: str
    org_id: str
    engagement_id: Optional[str]
    kind: str
    tool: str
    target_ref: Optional[str]
    status: str
    progress: int
    params: dict[str, Any]
    result: dict[str, Any]
    error: Optional[str]
    logs: list[Any]
    worker: Optional[str]
    retry_count: int
    started_at: Optional[datetime]
    finished_at: Optional[datetime]
    created_at: datetime
    demo: bool


class ToolOut(ORMModel):
    id: str
    name: str
    category: str
    installed: bool
    version: Optional[str]
    health: str
    last_checked_at: Optional[datetime]
    metadata_json: dict[str, Any]
