"""Seed data — realistic populated demo environment.

Creates 2 organizations with users, 20+ assets, an approved engagement,
findings, security events, detection rules, an incident, attack paths,
playbooks, evidence, reports and AI agents.

All lab-range data is labeled DEMO DATA / CONTROLLED LAB. Never presents
itself as live production telemetry.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy.orm import Session

from .db import SessionLocal, session_scope
from .models import (
    Agent,
    Asset,
    AssetRelationship,
    AttackPath,
    DetectionRule,
    Engagement,
    Event,
    Evidence,
    Finding,
    Incident,
    Organization,
    Playbook,
    ResponseAction,
    Retest,
    ScopeRule,
    User,
)
from .security import hash_password

DEMO_PASSWORD = "SentinelX-2026!"


def _ts(days_ago: float) -> datetime:
    return datetime.now(timezone.utc) - timedelta(days=days_ago)


def _prod_assets(org_id: str) -> list[Asset]:
    defs = [
        # name, type, ip, dns, tech, os, exposure, criticality, zone, env
        ("prod-vpn", "NETWORK_DEVICE", "10.0.0.1", "vpn.acme.example", "OpenVPN 2.6", "Linux", "INTERNET_FACING", "HIGH", "edge", "production"),
        ("corp-website", "WEB_APPLICATION", "10.0.1.5", "www.acme.example", "nginx 1.26", "Linux", "INTERNET_FACING", "LOW", "dmz", "production"),
        ("prod-web", "WEB_APPLICATION", "10.0.1.10", "web.acme.example", "Django 4.2", "Linux", "INTERNET_FACING", "HIGH", "dmz", "production"),
        ("prod-api", "API", "10.0.1.11", "api.acme.example", "FastAPI", "Linux", "INTERNET_FACING", "CRITICAL", "dmz", "production"),
        ("mail-server", "SERVER", "10.0.1.25", "mail.acme.example", "Postfix 3.8", "Linux", "INTERNET_FACING", "MEDIUM", "dmz", "production"),
        ("prod-db", "DATABASE", "10.0.2.20", "db.acme.example", "PostgreSQL 16", "Linux", "INTERNAL", "CRITICAL", "data", "production"),
        ("idp", "IDENTITY", "10.0.2.5", "idp.acme.example", "Keycloak 24", "Linux", "INTERNAL", "CRITICAL", "identity", "production"),
        ("fileshare", "SERVER", "10.0.2.30", "files.acme.example", "Samba", "Linux", "INTERNAL", "HIGH", "data", "production"),
        ("cicd-runner", "SERVER", "10.0.3.10", "cicd.acme.example", "GitLab Runner", "Linux", "INTERNAL", "HIGH", "dev", "production"),
        ("k8s-cluster", "KUBERNETES_RESOURCE", "10.0.3.20", "k8s.acme.example", "EKS 1.30", "Linux", "INTERNAL", "HIGH", "dev", "production"),
        ("container-registry", "CONTAINER", "10.0.3.30", "registry.acme.example", "Harbor", "Linux", "INTERNAL", "MEDIUM", "dev", "production"),
        ("workstation-jsmith", "WORKSTATION", "10.0.4.10", "ws-jsmith.acme.example", "Windows 11", "Windows", "INTERNAL", "MEDIUM", "office", "production"),
        ("laptop-rdoe", "LAPTOP", "10.0.4.20", "laptop-rdoe.acme.example", "macOS 14", "macOS", "INTERNAL", "MEDIUM", "office", "production"),
        ("acme-domain", "DOMAIN", None, "acme.example", None, None, "INTERNET_FACING", "HIGH", "edge", "production"),
        ("saas-okta", "SAAS_APPLICATION", None, "acme.okta.com", "Okta", None, "INTERNAL", "HIGH", "identity", "production"),
    ]
    return [
        Asset(
            org_id=org_id, name=name, asset_type=atype, ip_address=ip, dns_name=dns,
            technology=tech, os=os_, exposure=exposure, criticality=crit, zone=zone,
            environment=env, owner="IT Operations", last_seen=_ts(0.5), source="recon",
            metadata_json={"demo": True, "label": "DEMO DATA"},
        )
        for name, atype, ip, dns, tech, os_, exposure, crit, zone, env in defs
    ]


def _lab_assets(org_id: str) -> list[Asset]:
    defs = [
        # name, type, ip, dns, tech, os, exposure, criticality, zone, env
        ("lab-gateway", "NETWORK_DEVICE", "10.10.10.1", "lab-gateway.lab.local", "nginx 1.24", "Linux", "INTERNET_FACING", "HIGH", "dmz", "lab"),
        ("lab-web", "WEB_APPLICATION", "10.10.10.10", "lab-web.lab.local", "Flask 3.0", "Linux", "INTERNET_FACING", "CRITICAL", "dmz", "lab"),
        ("lab-api", "API", "10.10.10.11", "lab-api.lab.local", "FastAPI", "Linux", "INTERNAL", "CRITICAL", "app", "lab"),
        ("lab-db", "DATABASE", "10.10.10.20", "lab-db.lab.local", "PostgreSQL 15", "Linux", "INTERNAL", "CRITICAL", "data", "lab"),
        ("lab-admin", "WORKSTATION", "10.10.10.30", "lab-admin.lab.local", "Ubuntu Desktop", "Linux", "INTERNAL", "HIGH", "admin", "lab"),
        ("lab-cloud-bucket", "CLOUD_RESOURCE", "10.10.10.40", "lab-bucket.s3.lab.local", "S3-compatible", None, "INTERNET_FACING", "HIGH", "cloud", "lab"),
        ("lab-repo", "REPOSITORY", "10.10.10.50", "git.lab.local/lab-app", "Git", None, "INTERNAL", "MEDIUM", "dev", "lab"),
        ("lab-monitoring", "SERVER", "10.10.10.60", "lab-monitoring.lab.local", "Grafana", "Linux", "INTERNAL", "MEDIUM", "monitoring", "lab"),
    ]
    assets = []
    for name, atype, ip, dns, tech, os_, exposure, crit, zone, env in defs:
        assets.append(
            Asset(
                org_id=org_id, name=name, asset_type=atype, ip_address=ip, dns_name=dns,
                technology=tech, os=os_, exposure=exposure, criticality=crit, zone=zone,
                environment=env, owner="Security Team", last_seen=_ts(0.2), source="lab-range",
                metadata_json={"demo": True, "label": "CONTROLLED LAB"},
            )
        )
    return assets


def _lab_findings(org_id: str, assets: dict[str, Asset]) -> list[Finding]:
    web, api, db, bucket, repo = assets["lab-web"], assets["lab-api"], assets["lab-db"], assets["lab-cloud-bucket"], assets["lab-repo"]
    mail, prod_api, fileshare = assets["mail-server"], assets["prod-api"], assets["fileshare"]
    findings = [
        Finding(
            org_id=org_id, asset_id=web.id,
            title="Broken Object-Level Authorization in /api/orders/{id}",
            description="The endpoint returns another customer's order when the identifier is incremented; no ownership check. [CONTROLLED LAB]",
            severity="HIGH", cvss=8.1, cvss_vector="AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
            cwe="CWE-639", category="Authorization", endpoint="https://lab-web.lab.local/api/orders/1042",
            source="lab-range", status="VALIDATED", validated=True, confidence=0.95,
            attack_path_relevant=True, demo=True,
            remediation="Enforce object-level authorization on the server using the authenticated principal.",
            metadata_json={"scenario": "web_app_authorization", "demo": True, "label": "CONTROLLED LAB"},
            dedup_key="seed-web-bola", created_at=_ts(6), updated_at=_ts(1),
        ),
        Finding(
            org_id=org_id, asset_id=api.id,
            title="Broken Function-Level Authorization on Admin API",
            description="Non-admin API keys can invoke admin endpoints. [CONTROLLED LAB]",
            severity="CRITICAL", cvss=9.1, cwe="CWE-862", category="Authorization",
            endpoint="https://lab-api.lab.local/v1/admin/users", source="lab-range",
            status="VALIDATED", validated=True, confidence=0.96, attack_path_relevant=True, demo=True,
            remediation="Enforce role checks in the API gateway and service layer.",
            metadata_json={"scenario": "api_authorization", "demo": True, "label": "CONTROLLED LAB"},
            dedup_key="seed-api-bfla", created_at=_ts(10), updated_at=_ts(2),
        ),
        Finding(
            org_id=org_id, asset_id=web.id,
            title="Weak Session Cookie Entropy",
            description="Session tokens are predictable. [CONTROLLED LAB]",
            severity="MEDIUM", cvss=5.3, cwe="CWE-330", category="Session Management",
            endpoint="https://lab-web.lab.local/", source="lab-range", status="NEW",
            confidence=0.9, demo=True,
            remediation="Use a CSPRNG for session tokens.",
            metadata_json={"scenario": "web_app_authorization", "demo": True, "label": "CONTROLLED LAB"},
            dedup_key="seed-web-session", created_at=_ts(4), updated_at=_ts(4),
        ),
        Finding(
            org_id=org_id, asset_id=bucket.id,
            title="Publicly Readable Storage Bucket",
            description="Storage bucket allows anonymous list/read. [CONTROLLED LAB]",
            severity="HIGH", cvss=7.5, cwe="CWE-1188", category="Cloud Configuration",
            endpoint="https://lab-bucket.s3.lab.local/", source="lab-range", status="NEW",
            confidence=0.95, demo=True,
            remediation="Block public access and apply least-privilege bucket policies.",
            metadata_json={"scenario": "cloud_exposure", "demo": True, "label": "CONTROLLED LAB"},
            dedup_key="seed-bucket", created_at=_ts(3), updated_at=_ts(3),
        ),
        Finding(
            org_id=org_id, asset_id=repo.id,
            title="Hardcoded API Credential in Repository",
            description="A live API credential was committed to the repository. [CONTROLLED LAB]",
            severity="CRITICAL", cvss=9.8, cwe="CWE-798", category="Secret Exposure",
            endpoint="lab-app/.env.example", source="lab-range", status="TRIAGED",
            confidence=0.98, demo=True,
            remediation="Rotate the credential and purge it from git history.",
            metadata_json={"scenario": "secret_exposure", "demo": True, "label": "CONTROLLED LAB"},
            dedup_key="seed-secret", created_at=_ts(5), updated_at=_ts(5),
        ),
        Finding(
            org_id=org_id, asset_id=db.id,
            title="Database Reachable from Application Tier",
            description="The application tier can reach the database on a broad network path. [CONTROLLED LAB]",
            severity="MEDIUM", cvss=4.0, cwe="CWE-1188", category="Network Segmentation",
            endpoint="10.10.10.20:5432", source="nmap", status="NEW", confidence=0.7, demo=True,
            remediation="Restrict database access to the application tier only.",
            metadata_json={"demo": True, "label": "CONTROLLED LAB"},
            dedup_key="seed-db-exposure", created_at=_ts(2), updated_at=_ts(2),
        ),
        Finding(
            org_id=org_id, asset_id=mail.id,
            title="Legacy TLS Protocols Enabled on Mail Server",
            description="The mail server accepts TLS 1.0/1.1, allowing protocol downgrade. [DEMO DATA]",
            severity="MEDIUM", cvss=5.9, cve="CVE-2016-2183", cwe="CWE-327", category="Cryptographic Issues",
            endpoint="smtp://mail.acme.example:465", source="nmap", status="NEW", confidence=0.8, demo=True,
            remediation="Disable TLS 1.0/1.1 and require TLS 1.2+.",
            metadata_json={"demo": True, "label": "DEMO DATA", "scenario": "prod_mail_tls"},
            dedup_key="seed-mail-tls", created_at=_ts(9), updated_at=_ts(3),
        ),
        Finding(
            org_id=org_id, asset_id=prod_api.id,
            title="MFA Not Enforced for API Service Accounts",
            description="Service accounts authenticate without second factor. [DEMO DATA]",
            severity="HIGH", cvss=7.4, cwe="CWE-287", category="Authentication",
            endpoint="https://api.acme.example/v1", source="manual", status="TRIAGED", confidence=0.75, demo=True,
            remediation="Require MFA for privileged service accounts.",
            metadata_json={"demo": True, "label": "DEMO DATA", "scenario": "prod_api_mfa"},
            dedup_key="seed-prod-api-mfa", created_at=_ts(8), updated_at=_ts(2),
        ),
        Finding(
            org_id=org_id, asset_id=fileshare.id,
            title="World-Writable Share",
            description="A network share allows unauthenticated write access. [DEMO DATA]",
            severity="HIGH", cvss=6.5, cwe="CWE-732", category="Permissions",
            endpoint="smb://files.acme.example/shared", source="manual", status="NEW", confidence=0.7, demo=True,
            remediation="Remove world-writable ACLs and apply least privilege.",
            metadata_json={"demo": True, "label": "DEMO DATA", "scenario": "prod_fileshare"},
            dedup_key="seed-fileshare", created_at=_ts(7), updated_at=_ts(7),
        ),
    ]
    return findings


def _lab_events(org_id: str, assets: dict[str, Asset]) -> list[Event]:
    web, api, db = assets["lab-web"], assets["lab-api"], assets["lab-db"]
    rows = [
        (_ts(1.5), "lab-range", web.id, None, "network:port_scan", "low"),
        (_ts(1.45), "lab-range", web.id, "alice", "authentication:login_attempt", "medium"),
        (_ts(1.4), "lab-range", web.id, "alice", "web:api_request", "medium"),
        (_ts(1.35), "lab-range", web.id, "alice", "authentication:privilege_boundary", "high"),
        (_ts(1.3), "lab-range", api.id, "alice", "network:internal_connection", "high"),
        (_ts(1.25), "lab-range", db.id, "alice", "data:sensitive_access", "critical"),
        (_ts(0.9), "lab-range", bucket := assets["lab-cloud-bucket"].id, None, "cloud:public_bucket_probe", "medium"),
        (_ts(0.85), "lab-range", bucket, None, "cloud:anonymous_read", "high"),
        (_ts(0.5), "lab-range", assets["lab-repo"].id, None, "repo:secret_scan_hit", "high"),
    ]
    events = []
    for ts, source, asset_id, user_id, etype, sev in rows:
        events.append(
            Event(
                org_id=org_id, event_id=hashlib.sha256(f"{etype}|{asset_id}|{ts.isoformat()}".encode()).hexdigest()[:32],
                timestamp=ts, source=source, asset_id=asset_id, user_id=user_id,
                event_type=etype, severity=sev, demo=True,
                metadata={"label": "DEMO DATA", "stage": etype.split(":")[0]},
            )
        )
    return events


def _lab_rules(org_id: str) -> list[DetectionRule]:
    return [
        DetectionRule(
            org_id=org_id, rule_id="SIG-001", name="Sensitive Data Access",
            description="Detects access to sensitive data stores.",
            source="CUSTOM", severity="critical", version=1,
            mitre=["T1005"], status="DEPLOYED", regression_test=False,
            logic={"type": "signature", "match": {"event_type": "data:sensitive_access"}},
        ),
        DetectionRule(
            org_id=org_id, rule_id="SIG-002", name="Privilege Boundary Crossing",
            description="Detects privilege boundary events.",
            source="CUSTOM", severity="high", version=1,
            mitre=["T1548"], status="DEPLOYED",
            logic={"type": "signature", "match": {"event_type": "authentication:privilege_boundary"}},
        ),
        DetectionRule(
            org_id=org_id, rule_id="SIG-003", name="Web API Abuse",
            description="Detects repeated API requests (threshold).",
            source="CUSTOM", severity="medium", version=1,
            mitre=["T1059"], status="DEPLOYED",
            logic={"type": "threshold", "match": {"event_type": "web:api_request"}, "threshold": 3, "window_seconds": 300},
        ),
        DetectionRule(
            org_id=org_id, rule_id="SIG-PROP-001", name="Proposed: detect Lateral Movement (internal connection)",
            description="DRAFT proposal from purple-team gap.",
            source="CUSTOM", severity="high", version=1,
            mitre=["T1021"], status="DRAFT", regression_test=True,
            logic={"type": "signature", "match": {"event_type": "network:internal_connection"}},
        ),
    ]


def _lab_incident(org_id: str, findings: dict[str, Finding], events: list[Event]) -> Incident:
    inc = Incident(
        org_id=org_id, title="Suspicious access chain toward lab database",
        severity="high", status="INVESTIGATING",
        description="Correlated events show a privilege boundary crossing followed by sensitive data access. [DEMO DATA]",
        detection_sources=["SIG-001", "SIG-002", "SIG-003"],
        attack_techniques=["T1005", "T1548", "T1078"],
        affected_assets=[findings["web_app_authorization"].asset_id, findings["api_authorization"].asset_id],
        affected_users=["alice"],
        related_findings=[findings["web_app_authorization"].id, findings["api_authorization"].id],
        demo=True, created_at=_ts(1.5),
    )
    return inc


def _register_agents(db: Session) -> None:
    agents = [
        Agent(
            name="recon-agent", role="specialist", enabled=True,
            permissions=["assets:read", "scans:run"], tool_access=["nmap", "lab-range"],
            scope={"engagements_only": True},
            input_schema={"target_ref": "str", "engagement_id": "str"},
            output_schema={"assets": "list", "services": "list", "events": "list"},
        ),
        Agent(
            name="web-security-agent", role="specialist", enabled=True,
            permissions=["assets:read", "scans:run", "findings:write"], tool_access=["nuclei", "zap", "lab-range"],
            scope={"engagements_only": True},
            input_schema={"target_ref": "str", "engagement_id": "str"},
            output_schema={"findings": "list"},
        ),
        Agent(
            name="api-security-agent", role="specialist", enabled=True,
            permissions=["assets:read", "scans:run", "findings:write"], tool_access=["nuclei", "lab-range"],
            scope={"engagements_only": True},
            input_schema={"target_ref": "str", "engagement_id": "str"},
            output_schema={"findings": "list"},
        ),
        Agent(
            name="vulnerability-agent", role="specialist", enabled=True,
            permissions=["findings:read", "findings:write"], tool_access=[],
            scope={"read_only": True},
            input_schema={"findings": "list"},
            output_schema={"triage": "AITriageResponse"},
        ),
        Agent(
            name="attack-path-agent", role="specialist", enabled=True,
            permissions=["attack-paths:read"], tool_access=[],
            scope={"read_only": True},
            input_schema={"org_id": "str"},
            output_schema={"paths": "list"},
        ),
        Agent(
            name="soc-agent", role="specialist", enabled=True,
            permissions=["events:read", "incidents:read"], tool_access=[],
            scope={"read_only": True},
            input_schema={"incident_id": "str"},
            output_schema={"analysis": "AIIncidentAnalysis"},
        ),
        Agent(
            name="detection-agent", role="specialist", enabled=True,
            permissions=["rules:read", "rules:write"], tool_access=[],
            scope={"read_only": True, "draft_only": True},
            input_schema={"gap": "dict"},
            output_schema={"rule": "DetectionRuleCreate"},
        ),
        Agent(
            name="purple-agent", role="specialist", enabled=True,
            permissions=["purple:read", "purple:write"], tool_access=["lab-range"],
            scope={"engagements_only": True},
            input_schema={"scenario": "str", "engagement_id": "str"},
            output_schema={"coverage": "dict", "gaps": "list"},
        ),
    ]
    for a in agents:
        if not db.query(Agent).filter(Agent.name == a.name).first():
            db.add(a)


def seed_org(org_id: str, force: bool = False) -> dict:
    """Seed a single organization (idempotent unless force)."""
    with session_scope() as db:
        org = db.get(Organization, org_id)
        if org is None:
            return {"error": "org not found"}
        counts: dict[str, int] = {}

        # Users (emails scoped per organization)
        domain = org.slug + ".demo"
        users = {
            "admin": (f"admin@{domain}", "ORG_ADMIN"),
            "ciso": (f"ciso@{domain}", "CISO"),
            "pentester": (f"pentester@{domain}", "PENTESTER"),
            "soc": (f"soc@{domain}", "SOC_ANALYST"),
            "engineer": (f"engineer@{domain}", "SECURITY_ENGINEER"),
            "viewer": (f"viewer@{domain}", "VIEWER"),
        }
        for key, (email, role) in users.items():
            if not db.query(User).filter(User.email == email).first():
                db.add(User(org_id=org_id, email=email, name=key.capitalize(), password_hash=hash_password(DEMO_PASSWORD), role=role, status="ACTIVE"))
                counts[f"user:{key}"] = 1

        # Assets
        existing_assets = db.query(Asset).filter(Asset.org_id == org_id).count()
        if force or existing_assets == 0:
            assets = {a.name: a for a in _lab_assets(org_id) + _prod_assets(org_id)}
            for a in assets.values():
                db.add(a)
            db.flush()

            # Relationships: lab chain, prod chain
            rels = [
                (assets["lab-gateway"], assets["lab-web"], "NETWORK_ACCESS"),
                (assets["lab-web"], assets["lab-api"], "CAN_ACCESS"),
                (assets["lab-api"], assets["lab-db"], "CAN_ACCESS"),
                (assets["lab-admin"], assets["lab-db"], "CAN_ACCESS"),
                (assets["lab-web"], assets["lab-cloud-bucket"], "DATA_FLOW"),
                (assets["lab-repo"], assets["lab-api"], "DEPENDS_ON"),
                (assets["prod-vpn"], assets["prod-web"], "NETWORK_ACCESS"),
                (assets["prod-web"], assets["prod-api"], "CAN_ACCESS"),
                (assets["prod-api"], assets["prod-db"], "CAN_ACCESS"),
                (assets["idp"], assets["prod-api"], "TRUST"),
                (assets["idp"], assets["saas-okta"], "TRUST"),
                (assets["prod-api"], assets["fileshare"], "DATA_FLOW"),
                (assets["cicd-runner"], assets["container-registry"], "DEPENDS_ON"),
                (assets["prod-web"], assets["corp-website"], "NETWORK_ACCESS"),
            ]
            for src, dst, rtype in rels:
                db.add(AssetRelationship(org_id=org_id, source_asset_id=src.id, target_asset_id=dst.id, relationship_type=rtype, source="recon"))
            counts["assets"] = len(assets)

            # Findings
            findings = {f.metadata_json.get("scenario", f.dedup_key): f for f in _lab_findings(org_id, assets)}
            for f in findings.values():
                db.add(f)
            db.flush()

            # Evidence for validated findings
            for key in ("web_app_authorization", "api_authorization"):
                finding = findings[key]
                db.add(
                    Evidence(
                        org_id=org_id, finding_id=finding.id, engagement_id=None,
                        kind="TEST_RESULT", content_hash=hashlib.sha256(f"evidence-{finding.id}".encode()).hexdigest(),
                        data={"type": "controlled_validation", "label": "CONTROLLED LAB", "demo": True, "method": "GET", "url": finding.endpoint, "response_status": 200},
                        tool="lab-range", demo=True, captured_at=_ts(1), created_by="system",
                    )
                )
                finding.evidence_refs = [f"EV-{finding.id[:6]}"]

            # Events
            events = _lab_events(org_id, assets)
            for e in events:
                db.add(e)

            # Rules
            for r in _lab_rules(org_id):
                db.add(r)

            # Incident
            inc = _lab_incident(org_id, findings, events)
            db.add(inc)
            db.flush()
            from .services.incidents import add_timeline

            for e in events[:6]:
                add_timeline(db, inc, timestamp=e.timestamp, event_id=e.event_id, source=e.source, kind="OBSERVATION", message=f"{e.event_type} (severity {e.severity})")
            add_timeline(db, inc, timestamp=_ts(1.2), kind="DETECTION", source="SIG-001", message="Detection rule 'Sensitive Data Access' fired")
            counts["incidents"] = 1

            # Engagement (approved, lab scope) — enables RUN CONTROLLED SECURITY EXERCISE
            engagement = Engagement(
                org_id=org_id, name="Continuous Lab Assessment", description="Approved continuous assessment of the controlled cyber-range. [CONTROLLED LAB]",
                status="APPROVED",
                start_date=datetime.now(timezone.utc).date() - timedelta(days=1),
                end_date=datetime.now(timezone.utc).date() + timedelta(days=30),
                config={"allowed_tools": ["lab-range", "nmap", "nuclei"], "max_request_rate": 20, "destructive_testing": False, "data_handling": "no_pii"},
                approved_by="seed", approved_at=_ts(1), source="seed",
            )
            db.add(engagement)
            db.flush()
            db.add(ScopeRule(org_id=org_id, engagement_id=engagement.id, kind="INCLUDE", match_type="CIDR", value="10.10.10.0/24", note="Controlled lab range"))
            db.add(ScopeRule(org_id=org_id, engagement_id=engagement.id, kind="EXCLUDE", match_type="CIDR", value="10.0.0.0/16", note="Production network excluded from lab engagements"))
            counts["engagements"] = 1

            # Playbook + actions
            playbook = Playbook(
                org_id=org_id, name="Suspicious Account Containment",
                description="Contain a potentially compromised account.",
                triggers={"event_type": "data:sensitive_access"},
            )
            db.add(playbook)
            db.flush()
            db.add(ResponseAction(org_id=org_id, playbook_id=playbook.id, incident_id=inc.id, name="Create containment ticket", risk_level="LOW", action_type="CREATE_TICKET", requires_approval=False, status="EXECUTED", target={"entity": inc.id}))
            db.add(ResponseAction(org_id=org_id, playbook_id=playbook.id, incident_id=inc.id, name="Enable enhanced monitoring", risk_level="MEDIUM", action_type="ENABLE_MONITORING", requires_approval=False, status="EXECUTED", target={"scope": "app tier"}))
            db.add(ResponseAction(org_id=org_id, playbook_id=playbook.id, incident_id=inc.id, name="Revoke session for alice", risk_level="HIGH", action_type="REVOKE_SESSION", requires_approval=True, status="PENDING_APPROVAL", target={"username": "alice"}))
            db.add(ResponseAction(org_id=org_id, playbook_id=playbook.id, incident_id=inc.id, name="Isolate lab database", risk_level="CRITICAL", action_type="SERVICE_ISOLATION", requires_approval=True, status="PENDING_APPROVAL", target={"service": "lab-db"}))
            counts["playbooks"] = 1

            # Retest history
            db.add(Retest(org_id=org_id, finding_id=findings["web_app_authorization"].id, status="PASSED", before_result={"status": "VALIDATED"}, after_result={"reported_again": False}, created_by="seed"))
            counts["retests"] = 1

            db.commit()

            # Attack paths (compute after findings/relationships exist)
            from .services.attack_paths import compute_attack_paths

            paths = compute_attack_paths(db, org_id)
            counts["attack_paths"] = len(paths)

            # Seed reports
            from .services.reports import generate_report

            for rtype in ("executive", "pentest", "purple", "remediation"):
                try:
                    generate_report(db, org_id, rtype, engagement_id=engagement.id, created_by="seed")
                except Exception:  # noqa: BLE001
                    pass
            counts["reports"] = 4

        _register_agents(db)
        db.commit()
        return {"org": org.slug, "seeded": counts or {"already_populated": True}}


def seed_all(force: bool = False) -> dict:
    with session_scope() as db:
        # Platform orgs
        acme = db.query(Organization).filter(Organization.slug == "acme").first()
        if acme is None:
            acme = Organization(name="Acme Corporation", slug="acme", plan="enterprise", is_demo=True)
            db.add(acme)
            db.flush()
        globex = db.query(Organization).filter(Organization.slug == "globex").first()
        if globex is None:
            globex = Organization(name="Globex Industries", slug="globex", plan="enterprise", is_demo=True)
            db.add(globex)
            db.flush()

        # Platform super admin
        if not db.query(User).filter(User.email == "root@sentinelx.local").first():
            db.add(User(org_id=None, email="root@sentinelx.local", name="Platform Root", password_hash=hash_password(DEMO_PASSWORD), role="SUPER_ADMIN", status="ACTIVE"))
        _register_agents(db)
        db.commit()
        org_ids = [acme.id, globex.id]

    results = {}
    for org_id in org_ids:
        results[org_id] = seed_org(org_id, force=force)
    return results


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Seed SENTINEL X demo data")
    parser.add_argument("--force", action="store_true", help="Re-seed even if populated")
    args = parser.parse_args()
    results = seed_all(force=args.force)
    for org_id, result in results.items():
        print(f"org {org_id}: {result}")


if __name__ == "__main__":
    main()
