"""Asset inventory service: upsert assets/services from normalized tool output."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from ..models import Asset, Service


def upsert_assets_and_services(
    db: Session,
    org_id: str,
    normalized_assets: list[Any],
    normalized_services: list[Any],
    source: str = "tool",
) -> dict[str, str]:
    """Create or update assets by (org, ip/dns), then attach services."""
    now = datetime.now(timezone.utc)
    asset_map: dict[str, Asset] = {}
    created = 0
    updated = 0
    for na in normalized_assets:
        existing = None
        if na.ip_address:
            existing = (
                db.query(Asset)
                .filter(Asset.org_id == org_id, Asset.ip_address == na.ip_address)
                .first()
            )
        if existing is None and na.dns_name:
            existing = (
                db.query(Asset)
                .filter(Asset.org_id == org_id, Asset.dns_name == na.dns_name)
                .first()
            )
        if existing is None:
            asset = Asset(
                org_id=org_id,
                name=na.name,
                asset_type=na.asset_type,
                ip_address=na.ip_address,
                dns_name=na.dns_name,
                technology=na.technology,
                os=na.os,
                exposure=na.exposure,
                last_seen=now,
                source=source,
                metadata_json=na.metadata,
            )
            db.add(asset)
            db.flush()
            asset_map[na.ip_address or na.name] = asset
            created += 1
        else:
            existing.last_seen = now
            if na.technology and not existing.technology:
                existing.technology = na.technology
            if na.os and not existing.os:
                existing.os = na.os
            if na.exposure != "UNKNOWN" and existing.exposure == "UNKNOWN":
                existing.exposure = na.exposure
            asset_map[na.ip_address or na.name] = existing
            updated += 1

    service_created = 0
    for ns in normalized_services:
        asset = asset_map.get(ns.asset_ip) or _find_by_ip(db, org_id, ns.asset_ip)
        if asset is None:
            continue
        exists = (
            db.query(Service)
            .filter(Service.asset_id == asset.id, Service.port == ns.port, Service.name == ns.name)
            .first()
        )
        if exists is None:
            db.add(
                Service(
                    org_id=org_id,
                    asset_id=asset.id,
                    name=ns.name,
                    port=ns.port,
                    protocol=ns.protocol,
                    version=ns.version,
                    technology=ns.technology or ns.name,
                    state=ns.state,
                    metadata_json=ns.metadata,
                )
            )
            service_created += 1
        else:
            exists.version = ns.version or exists.version
            exists.technology = ns.technology or exists.technology
    db.commit()
    return {"assets_created": created, "assets_updated": updated, "services_created": service_created}


def _find_by_ip(db: Session, org_id: str, ip: str | None) -> Asset | None:
    if not ip:
        return None
    return db.query(Asset).filter(Asset.org_id == org_id, Asset.ip_address == ip).first()
