"""Asset inventory, services, identities and relationships."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..db import Base, json_type
from .core import TimestampMixin, new_id

ASSET_TYPES = [
    "HOST", "SERVER", "LAPTOP", "WORKSTATION", "NETWORK_DEVICE",
    "WEB_APPLICATION", "API", "DATABASE", "CONTAINER", "KUBERNETES_RESOURCE",
    "CLOUD_RESOURCE", "IDENTITY", "SERVICE_ACCOUNT", "DOMAIN", "CERTIFICATE",
    "REPOSITORY", "SAAS_APPLICATION",
]
EXPOSURE_LEVELS = ["INTERNET_FACING", "INTERNAL", "EXTERNAL", "UNKNOWN"]


class Asset(Base, TimestampMixin):
    __tablename__ = "assets"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    asset_type: Mapped[str] = mapped_column(String(32), default="HOST", index=True)
    owner: Mapped[str | None] = mapped_column(String(255), nullable=True)
    environment: Mapped[str | None] = mapped_column(String(64), nullable=True)
    criticality: Mapped[str] = mapped_column(String(16), default="MEDIUM", index=True)
    zone: Mapped[str | None] = mapped_column(String(64), nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    dns_name: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    technology: Mapped[str | None] = mapped_column(String(255), nullable=True)
    os: Mapped[str | None] = mapped_column(String(255), nullable=True)
    exposure: Mapped[str] = mapped_column(String(32), default="UNKNOWN", index=True)
    auth_required: Mapped[bool] = mapped_column(default=True)
    status: Mapped[str] = mapped_column(String(16), default="ACTIVE")
    managed: Mapped[bool] = mapped_column(default=True)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    source: Mapped[str] = mapped_column(String(64), default="manual")
    metadata_json: Mapped[dict] = mapped_column(json_type(), default=dict)

    services = relationship("Service", back_populates="asset", cascade="all, delete-orphan")
    identities = relationship("Identity", back_populates="asset", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="asset")


class Service(Base, TimestampMixin):
    __tablename__ = "services"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id"), index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str | None] = mapped_column(String(16), nullable=True)
    version: Mapped[str | None] = mapped_column(String(255), nullable=True)
    technology: Mapped[str | None] = mapped_column(String(255), nullable=True)
    state: Mapped[str] = mapped_column(String(16), default="open")
    metadata_json: Mapped[dict] = mapped_column(json_type(), default=dict)

    asset = relationship("Asset", back_populates="services")


class Technology(Base, TimestampMixin):
    __tablename__ = "technologies"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    asset_id: Mapped[str | None] = mapped_column(ForeignKey("assets.id"), index=True, nullable=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    version: Mapped[str | None] = mapped_column(String(255), nullable=True)
    category: Mapped[str | None] = mapped_column(String(64), nullable=True)
    source: Mapped[str | None] = mapped_column(String(64), nullable=True)
    metadata_json: Mapped[dict] = mapped_column(json_type(), default=dict)


class Identity(Base, TimestampMixin):
    __tablename__ = "identities"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    asset_id: Mapped[str | None] = mapped_column(ForeignKey("assets.id"), index=True, nullable=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    identity_type: Mapped[str] = mapped_column(String(32), default="USER")
    username: Mapped[str | None] = mapped_column(String(255), nullable=True)
    privileged: Mapped[bool] = mapped_column(default=False)
    roles: Mapped[list] = mapped_column(json_type(), default=list)
    metadata_json: Mapped[dict] = mapped_column(json_type(), default=dict)

    asset = relationship("Asset", back_populates="identities")


class AssetRelationship(Base, TimestampMixin):
    __tablename__ = "asset_relationships"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    source_asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id"), index=True)
    target_asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id"), index=True)
    relationship_type: Mapped[str] = mapped_column(String(32), default="DEPENDS_ON", index=True)
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    source: Mapped[str] = mapped_column(String(64), default="manual")
    metadata_json: Mapped[dict] = mapped_column(json_type(), default=dict)
