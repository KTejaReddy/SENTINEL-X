"""Attack-path directed graph models."""
from __future__ import annotations

from sqlalchemy import Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..db import Base, json_type
from .core import TimestampMixin, new_id


class AttackPath(Base, TimestampMixin):
    __tablename__ = "attack_paths"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    entry_asset_id: Mapped[str | None] = mapped_column(ForeignKey("assets.id"), nullable=True)
    target_asset_id: Mapped[str | None] = mapped_column(ForeignKey("assets.id"), nullable=True)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0, index=True)
    status: Mapped[str] = mapped_column(String(16), default="ACTIVE", index=True)  # ACTIVE|BLOCKED|RESOLVED
    stages: Mapped[list] = mapped_column(json_type(), default=list)
    metadata_json: Mapped[dict] = mapped_column(json_type(), default=dict)

    nodes = relationship("AttackPathNode", back_populates="attack_path", cascade="all, delete-orphan")


class AttackPathNode(Base, TimestampMixin):
    __tablename__ = "attack_path_nodes"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    attack_path_id: Mapped[str] = mapped_column(ForeignKey("attack_paths.id"), index=True)
    ordinal: Mapped[int] = mapped_column(Integer, default=0)
    asset_id: Mapped[str | None] = mapped_column(ForeignKey("assets.id"), nullable=True)
    label: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(32), default="TRANSITION")  # ENTRY|TRANSITION|DESTINATION
    node_type: Mapped[str] = mapped_column(String(32), default="ASSET")
    evidence_refs: Mapped[list] = mapped_column(json_type(), default=list)
    detail: Mapped[dict] = mapped_column(json_type(), default=dict)

    attack_path = relationship("AttackPath", back_populates="nodes")
