"""/assets, /attack-surface routes."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import Asset, AssetRelationship, Service
from ..schemas import AssetCreate, AssetOut, AssetUpdate, ServiceOut
from .deps import (
    RequestContext,
    check_permission,
    ctx_audit,
    get_request_context,
    paginate,
    require_org,
)

router = APIRouter(tags=["assets"])


@router.get("/assets", response_model=list[AssetOut])
def list_assets(
    ctx: RequestContext = Depends(require_org),
    db: Session = Depends(get_db),
    asset_type: str | None = None,
    exposure: str | None = None,
    criticality: str | None = None,
    search: str | None = None,
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=200),
):
    check_permission(ctx.user, "assets:read")
    q = db.query(Asset).filter(Asset.org_id == ctx.org.id)
    if asset_type:
        q = q.filter(Asset.asset_type == asset_type.upper())
    if exposure:
        q = q.filter(Asset.exposure == exposure.upper())
    if criticality:
        q = q.filter(Asset.criticality == criticality.upper())
    if search:
        like = f"%{search}%"
        q = q.filter((Asset.name.ilike(like)) | (Asset.ip_address.ilike(like)) | (Asset.dns_name.ilike(like)))
    return paginate(q.order_by(Asset.created_at.desc()), page, size)


@router.get("/assets/{asset_id}", response_model=AssetOut)
def get_asset(asset_id: str, ctx: RequestContext = Depends(require_org), db: Session = Depends(get_db)):
    check_permission(ctx.user, "assets:read")
    asset = db.query(Asset).filter(Asset.id == asset_id, Asset.org_id == ctx.org.id).first()
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found")
    return asset


@router.post("/assets", response_model=AssetOut)
def create_asset(body: AssetCreate, ctx: RequestContext = Depends(require_org), db: Session = Depends(get_db)):
    check_permission(ctx.user, "assets:write")
    payload = body.model_dump(exclude={"metadata"})
    asset = Asset(org_id=ctx.org.id, **payload)
    asset.metadata_json = body.metadata
    db.add(asset)
    db.commit()
    db.refresh(asset)
    ctx_audit(ctx, "asset.create", resource_type="asset", resource_id=asset.id, detail={"name": asset.name, "type": asset.asset_type})
    return asset


@router.patch("/assets/{asset_id}", response_model=AssetOut)
def update_asset(asset_id: str, body: AssetUpdate, ctx: RequestContext = Depends(require_org), db: Session = Depends(get_db)):
    check_permission(ctx.user, "assets:write")
    asset = db.query(Asset).filter(Asset.id == asset_id, Asset.org_id == ctx.org.id).first()
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found")
    for key, value in body.model_dump(exclude_none=True).items():
        setattr(asset, key, value)
    asset.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(asset)
    ctx_audit(ctx, "asset.update", resource_type="asset", resource_id=asset.id, detail=body.model_dump(exclude_none=True))
    return asset


@router.get("/assets/{asset_id}/services", response_model=list[ServiceOut])
def asset_services(asset_id: str, ctx: RequestContext = Depends(require_org), db: Session = Depends(get_db)):
    check_permission(ctx.user, "assets:read")
    return db.query(Service).filter(Service.asset_id == asset_id, Service.org_id == ctx.org.id).all()


@router.get("/assets/{asset_id}/relationships")
def asset_relationships(asset_id: str, ctx: RequestContext = Depends(require_org), db: Session = Depends(get_db)):
    check_permission(ctx.user, "assets:read")
    rels = (
        db.query(AssetRelationship)
        .filter(
            AssetRelationship.org_id == ctx.org.id,
            (AssetRelationship.source_asset_id == asset_id) | (AssetRelationship.target_asset_id == asset_id),
        )
        .all()
    )
    return [
        {
            "id": r.id,
            "source_asset_id": r.source_asset_id,
            "target_asset_id": r.target_asset_id,
            "relationship_type": r.relationship_type,
            "detail": r.detail,
        }
        for r in rels
    ]


@router.post("/assets/{asset_id}/relationships")
def create_relationship(
    asset_id: str,
    body: dict,
    ctx: RequestContext = Depends(require_org),
    db: Session = Depends(get_db),
):
    check_permission(ctx.user, "assets:write")
    target_id = body.get("target_asset_id")
    rel_type = body.get("relationship_type", "CAN_ACCESS")
    source = db.query(Asset).filter(Asset.id == asset_id, Asset.org_id == ctx.org.id).first()
    target = db.query(Asset).filter(Asset.id == target_id, Asset.org_id == ctx.org.id).first()
    if source is None or target is None:
        raise HTTPException(status_code=404, detail="Source or target asset not found")
    rel = AssetRelationship(
        org_id=ctx.org.id, source_asset_id=source.id, target_asset_id=target.id,
        relationship_type=rel_type, detail=body.get("detail"),
    )
    db.add(rel)
    db.commit()
    db.refresh(rel)
    ctx_audit(ctx, "asset.relationship.create", resource_type="asset_relationship", resource_id=rel.id, detail={"source": source.id, "target": target.id, "type": rel_type})
    return {"id": rel.id, "source_asset_id": rel.source_asset_id, "target_asset_id": rel.target_asset_id, "relationship_type": rel.relationship_type}


# ---------- Attack Surface ----------

@router.get("/attack-surface")
def attack_surface(ctx: RequestContext = Depends(require_org), db: Session = Depends(get_db)):
    check_permission(ctx.user, "attack-surface:read")
    org_id = ctx.org.id
    since_day = datetime.now(timezone.utc) - timedelta(days=1)
    since_week = datetime.now(timezone.utc) - timedelta(days=7)
    total = db.query(Asset).filter(Asset.org_id == org_id).count()
    internet = db.query(Asset).filter(Asset.org_id == org_id, Asset.exposure == "INTERNET_FACING").count()
    new_week = db.query(Asset).filter(Asset.org_id == org_id, Asset.created_at >= since_week).count()
    changed_day = db.query(Asset).filter(Asset.org_id == org_id, Asset.updated_at >= since_day).count()
    unmanaged = db.query(Asset).filter(Asset.org_id == org_id, Asset.managed.is_(False)).count()
    high_risk = (
        db.query(Asset)
        .filter(Asset.org_id == org_id, Asset.criticality.in_(["CRITICAL", "HIGH"]), Asset.exposure == "INTERNET_FACING")
        .count()
    )
    changes = (
        db.query(Asset)
        .filter(Asset.org_id == org_id, Asset.updated_at >= since_day)
        .order_by(Asset.updated_at.desc())
        .limit(25)
        .all()
    )
    return {
        "total_assets": total,
        "internet_exposed": internet,
        "new_this_week": new_week,
        "changed_today": changed_day,
        "unmanaged": unmanaged,
        "high_risk": high_risk,
        "changes": [
            {
                "asset_id": a.id,
                "name": a.name,
                "asset_type": a.asset_type,
                "exposure": a.exposure,
                "criticality": a.criticality,
                "changed_at": a.updated_at.isoformat(),
            }
            for a in changes
        ],
    }
