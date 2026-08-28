"""Attack-Path Engine.

Builds a directed graph from assets, relationships and findings, then finds
realistic paths from entry points (internet-facing or lab entry assets) to
high-value destinations (databases / critical assets).

Paths are recomputed from live data — the graph is not decorative.
"""
from __future__ import annotations

from collections import deque
from typing import Any, Optional

from sqlalchemy.orm import Session

from ..models import Asset, AssetRelationship, AttackPath, AttackPathNode, Finding, Incident

HIGH_VALUE_TYPES = {"DATABASE", "CLOUD_RESOURCE", "KUBERNETES_RESOURCE"}
TRANSITION_RELATIONSHIPS = {"CAN_ACCESS", "DATA_FLOW", "TRUST", "DEPENDS_ON", "NETWORK_ACCESS"}
MAX_PATH_DEPTH = 6
MAX_PATHS = 20

NODE_LABEL = {
    "WEB_APPLICATION": "Web App",
    "API": "API",
    "DATABASE": "Database",
    "SERVER": "Server",
    "CONTAINER": "Container",
    "IDENTITY": "Identity",
    "CLOUD_RESOURCE": "Cloud",
}


def _entry_assets(db: Session, org_id: str) -> list[Asset]:
    return (
        db.query(Asset)
        .filter(Asset.org_id == org_id, Asset.exposure == "INTERNET_FACING")
        .all()
    )


def _high_value_assets(db: Session, org_id: str) -> list[Asset]:
    from sqlalchemy import or_

    return (
        db.query(Asset)
        .filter(
            Asset.org_id == org_id,
            or_(Asset.asset_type.in_(HIGH_VALUE_TYPES), Asset.criticality.in_(["CRITICAL", "HIGH"])),
        )
        .all()
    )


def _adjacency(db: Session, org_id: str, asset_ids: set[str]) -> dict[str, list[tuple[str, str, str]]]:
    """asset_id -> [(neighbor_id, relationship_type, detail)]"""
    rels = db.query(AssetRelationship).filter(
        AssetRelationship.org_id == org_id,
        AssetRelationship.relationship_type.in_(TRANSITION_RELATIONSHIPS),
    ).all()
    adj: dict[str, list[tuple[str, str, str]]] = {aid: [] for aid in asset_ids}
    for r in rels:
        if r.source_asset_id in adj and r.target_asset_id in adj:
            adj[r.source_asset_id].append((r.target_asset_id, r.relationship_type, r.detail or ""))
    return adj


def _findings_by_asset(db: Session, org_id: str) -> dict[str, list[Finding]]:
    findings = (
        db.query(Finding)
        .filter(Finding.org_id == org_id, Finding.asset_id.isnot(None), Finding.status.notin_(["CLOSED", "VERIFIED", "FIXED"]))
        .all()
    )
    by_asset: dict[str, list[Finding]] = {}
    for f in findings:
        by_asset.setdefault(f.asset_id, []).append(f)
    return by_asset


def _bfs_paths(
    adj: dict[str, list[tuple[str, str, str]]],
    entry_ids: list[str],
    terminal_ids: set[str],
) -> list[list[str]]:
    """BFS shortest paths from entries to terminal (high-value) destinations."""
    paths: list[list[str]] = []
    for entry in entry_ids:
        queue: deque[tuple[str, list[str]]] = deque([(entry, [entry])])
        while queue:
            node, path = queue.popleft()
            if len(path) > MAX_PATH_DEPTH:
                continue
            if node in terminal_ids and len(path) >= 2:
                paths.append(path)
                continue
            for neighbor, _, _ in adj.get(node, []):
                if neighbor not in path:
                    queue.append((neighbor, path + [neighbor]))
        if len(paths) >= MAX_PATHS:
            break
    return paths


def compute_attack_paths(db: Session, org_id: str, force: bool = False) -> list[AttackPath]:
    """Recompute active attack paths for an organization from live data."""
    entries = _entry_assets(db, org_id)
    targets = _high_value_assets(db, org_id)
    if not entries or not targets:
        return []

    all_assets = db.query(Asset).filter(Asset.org_id == org_id).all()
    asset_map = {a.id: a for a in all_assets}
    asset_ids = set(asset_map.keys())
    adj = _adjacency(db, org_id, asset_ids)

    # Findings can create transition edges when they reference another asset's
    # endpoint (e.g. web app reaching an internal service).
    findings_by_asset = _findings_by_asset(db, org_id)
    for asset_id, findings in findings_by_asset.items():
        for f in findings:
            for other_id, other in asset_map.items():
                if other_id == asset_id:
                    continue
                if other.ip_address and other.ip_address in (f.endpoint or ""):
                    adj.setdefault(asset_id, []).append((other_id, "VULNERABILITY", f"finding {f.id} reaches {other.name}"))

    # Prefer database-type destinations; fall back to other high-value targets.
    terminal_pref = {t.id for t in targets if t.asset_type in HIGH_VALUE_TYPES}
    raw_paths = _bfs_paths(adj, [e.id for e in entries], terminal_pref)
    if not raw_paths:
        raw_paths = _bfs_paths(adj, [e.id for e in entries], {t.id for t in targets})

    # Keep only paths where at least one node carries a finding (evidence-backed)
    evidence_paths: list[list[str]] = []
    for p in raw_paths:
        if any(node_id in findings_by_asset for node_id in p):
            evidence_paths.append(p)
    if not evidence_paths:
        return []

    from .risk import score_path

    # Mark findings on these paths as attack-path relevant
    relevant_ids: set[str] = set()
    for p in evidence_paths:
        for node_id in p:
            for f in findings_by_asset.get(node_id, []):
                relevant_ids.add(f.id)
    if relevant_ids:
        db.query(Finding).filter(Finding.id.in_(relevant_ids)).update(
            {"attack_path_relevant": True}, synchronize_session=False
        )
        db.commit()

    # Compute path risk and persist
    created: list[AttackPath] = []
    for i, p in enumerate(evidence_paths[:MAX_PATHS]):
        entry_asset = asset_map[p[0]]
        dest_asset = asset_map[p[-1]]
        name = f"Path {i+1}: {entry_asset.name} → {dest_asset.name}"
        existing = (
            db.query(AttackPath)
            .filter(AttackPath.org_id == org_id, AttackPath.name == name, AttackPath.status == "ACTIVE")
            .first()
        )
        ap = existing
        if ap is None:
            ap = AttackPath(
                org_id=org_id,
                name=name,
                entry_asset_id=p[0],
                target_asset_id=p[-1],
                description=f"Attack path from {entry_asset.name} to {dest_asset.name} through {len(p)} hops",
                status="ACTIVE",
            )
            db.add(ap)
            db.flush()
        else:
            ap.nodes.clear()
        for ordinal, node_id in enumerate(p):
            asset = asset_map[node_id]
            findings = findings_by_asset.get(node_id, [])
            ap.nodes.append(
                AttackPathNode(
                    ordinal=ordinal,
                    asset_id=node_id,
                    label=asset.name,
                    role="ENTRY" if ordinal == 0 else ("DESTINATION" if ordinal == len(p) - 1 else "TRANSITION"),
                    node_type=asset.asset_type,
                    evidence_refs=[f.id for f in findings],
                    detail={
                        "criticality": asset.criticality,
                        "exposure": asset.exposure,
                        "asset_type": asset.asset_type,
                        "findings": [{"id": f.id, "title": f.title, "severity": f.severity, "validated": f.validated} for f in findings],
                    },
                )
            )
        scoring = score_path(ap, findings_by_asset)
        ap.risk_score = scoring["score"]
        ap.metadata_json = {**(ap.metadata_json or {}), "risk": scoring, "recomputed_at": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat()}
        db.flush()
        created.append(ap)
    db.commit()
    return created


def get_graph(db: Session, org_id: str) -> dict[str, Any]:
    """Return the org's attack graph (nodes + edges) for the UI."""
    assets = db.query(Asset).filter(Asset.org_id == org_id).all()
    rels = db.query(AssetRelationship).filter(AssetRelationship.org_id == org_id).all()
    findings = (
        db.query(Finding)
        .filter(Finding.org_id == org_id, Finding.status.notin_(["CLOSED", "VERIFIED", "FIXED"]))
        .all()
    )
    incidents = db.query(Incident).filter(Incident.org_id == org_id, Incident.status.in_(["OPEN", "INVESTIGATING", "CONTAINED"])).all()
    paths = db.query(AttackPath).filter(AttackPath.org_id == org_id, AttackPath.status == "ACTIVE").all()
    path_edges: set[tuple[str, str]] = set()
    for p in paths:
        for a, b in zip(p.nodes, p.nodes[1:]):
            if a.asset_id and b.asset_id:
                path_edges.add((a.asset_id, b.asset_id))

    nodes = [
        {
            "id": a.id,
            "label": a.name,
            "type": a.asset_type,
            "criticality": a.criticality,
            "exposure": a.exposure,
            "finding_count": sum(1 for f in findings if f.asset_id == a.id),
            "critical_findings": sum(1 for f in findings if f.asset_id == a.id and f.severity in {"CRITICAL", "HIGH"}),
            "incident": any(i for i in incidents if a.id in (i.affected_assets or [])),
            "in_attack_path": any(a.id in {n.asset_id for n in p.nodes} for p in paths),
        }
        for a in assets
    ]
    edges = [
        {"id": f"r-{r.id}", "source": r.source_asset_id, "target": r.target_asset_id, "type": r.relationship_type, "detail": r.detail}
        for r in rels
    ]
    for s, t in path_edges:
        if not any(e["source"] == s and e["target"] == t and e["type"] == "ATTACK_PATH" for e in edges):
            edges.append({"id": f"ap-{s}-{t}", "source": s, "target": t, "type": "ATTACK_PATH"})
    return {"nodes": nodes, "edges": edges}
