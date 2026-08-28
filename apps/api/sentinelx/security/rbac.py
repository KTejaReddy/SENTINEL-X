"""Role-based access control.

Roles are defined centrally. Permission checks are enforced at the API and
service layer — never only in the frontend.

Permission strings follow `resource:action` naming, e.g. `assets:write`.
The special permission `*` grants everything (SUPER_ADMIN only).
"""
from __future__ import annotations

ROLES = [
    "SUPER_ADMIN",
    "ORG_ADMIN",
    "CISO",
    "SECURITY_ADMIN",
    "PENTESTER",
    "SOC_ANALYST",
    "SECURITY_ENGINEER",
    "DEVELOPER",
    "AUDITOR",
    "VIEWER",
]

READ_ALL = [
    "assets:read", "attack-surface:read", "engagements:read", "scans:read",
    "findings:read", "evidence:read", "attack-paths:read", "events:read",
    "rules:read", "incidents:read", "hunts:run", "playbooks:read",
    "responses:read", "remediation:read", "retests:read", "reports:read",
    "ai:use", "purple:read", "users:read", "audit:read", "system:read",
    "notifications:read", "tools:read",
]

ROLE_PERMISSIONS: dict[str, set[str]] = {
    "SUPER_ADMIN": {"*"},
    "ORG_ADMIN": set(READ_ALL) | {
        "assets:write", "users:write", "org:manage", "engagements:write",
        "engagements:approve", "policy:manage", "system:write",
        "responses:write", "responses:approve", "incidents:write",
        "remediation:write", "retests:run", "playbooks:write", "reports:generate",
    },
    "CISO": set(READ_ALL) | {
        "reports:generate", "incidents:write", "remediation:write",
        "risk:read", "purple:write", "policy:manage",
    },
    "SECURITY_ADMIN": set(READ_ALL) | {
        "assets:write", "findings:write", "rules:write", "incidents:write",
        "playbooks:write", "responses:write", "responses:approve",
        "remediation:write", "retests:run", "engagements:write",
        "engagements:approve", "purple:write", "events:ingest",
    },
    "PENTESTER": {
        "assets:read", "attack-surface:read", "engagements:read", "engagements:write",
        "scans:read", "scans:run", "scans:approve", "findings:read", "findings:write",
        "evidence:read", "evidence:write", "attack-paths:read", "reports:read",
        "reports:generate", "retests:run", "ai:use", "purple:read", "jobs:manage",
        "users:read", "system:read", "notifications:read", "tools:read", "tools:run",
    },
    "SOC_ANALYST": {
        "assets:read", "events:read", "events:ingest", "rules:read", "incidents:read",
        "incidents:write", "hunts:run", "playbooks:read", "responses:read",
        "responses:write", "attack-paths:read", "evidence:read", "reports:read",
        "ai:use", "purple:read", "users:read", "system:read", "notifications:read",
    },
    "SECURITY_ENGINEER": {
        "assets:read", "findings:read", "findings:write", "remediation:read",
        "remediation:write", "retests:read", "retests:run", "evidence:read",
        "evidence:write", "rules:read", "rules:write", "incidents:read",
        "attack-paths:read", "reports:read", "reports:generate", "ai:use",
        "users:read", "system:read", "notifications:read", "engagements:read",
    },
    "DEVELOPER": {
        "assets:read", "findings:read", "remediation:read", "remediation:write",
        "retests:read", "reports:read", "evidence:read", "incidents:read",
        "ai:use", "users:read", "system:read", "notifications:read",
    },
    "AUDITOR": {
        "audit:read", "reports:read", "assets:read", "findings:read",
        "incidents:read", "events:read", "system:read", "users:read",
    },
    "VIEWER": {
        "assets:read", "findings:read", "incidents:read", "events:read",
        "attack-paths:read", "reports:read", "users:read", "system:read",
        "notifications:read",
    },
}


def has_permission(role: str | None, permission: str) -> bool:
    perms = ROLE_PERMISSIONS.get(role or "", set())
    if "*" in perms:
        return True
    return permission in perms
