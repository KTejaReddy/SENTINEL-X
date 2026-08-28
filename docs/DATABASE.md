# SENTINEL X — Database model

PostgreSQL in production (SQLite locally). Migrations via Alembic
(`apps/api/alembic/`). Every tenant-owned table has `org_id`; all reads are
scoped server-side.

## Core (identity & tenancy)

| Table | Key fields |
|---|---|
| `organizations` | name, slug, plan, status |
| `teams` | org_id, name |
| `users` | org_id, email, password_hash, role, mfa_enabled, mfa_secret, status |
| `refresh_tokens` | user_id, token_hash, expires_at, revoked_at, family_id |

## Assets

| Table | Key fields |
|---|---|
| `assets` | org_id, name, asset_type, ip, dns, os, technology, environment, exposure, criticality, owner, status, first_seen, last_seen |
| `services` | asset_id, port, protocol, service, version, banner |
| `technologies` | asset_id, name, version, category |
| `identities` | org_id, name, identity_type, privileged, source |
| `asset_relationships` | org_id, source_id, target_id, relation |

## Offensive

| Table | Key fields |
|---|---|
| `engagements` | org_id, name, status (DRAFT…CLOSED), start/end window, allowed_tools, rate_limit, destructive_allowed, data_handling, created_by |
| `scope_rules` | engagement_id, kind (ALLOW/DENY), value (CIDR/hostname) |
| `tools` | name, category, availability, version |
| `jobs` | org_id, engagement_id, tool, target, status (queued/running/paused/cancelled/failed/completed), progress, error, params, result, started_at, finished_at |
| `scans` | job_id, tool, target, summary |
| `findings` | org_id, asset_id, engagement_id, job_id, title, severity, cvss, cwe, status, validation_status, evidence refs, mitre, ai_triage |
| `evidence` | org_id, finding/incident/job refs, evidence_type, content_hash, storage_path, audit_history |
| `remediations` | org_id, finding_id, status, due_date, owner, notes |
| `retests` | org_id, finding_id, remediation_id, status (PASSED/FAILED/…), evidence, regression |

## Attack paths

| Table | Key fields |
|---|---|
| `attack_paths` | org_id, entry_node, target_node, score, severity, path (JSON), description |
| `attack_path_nodes` | path_id, node_type, asset_id, identity, label, data |

## Defensive

| Table | Key fields |
|---|---|
| `events` | org_id, event_type, severity, source, asset_id, user_id, event_data (JSON), received_at |
| `detection_rules` | org_id, name, description, source (sigma/suricata/custom), severity, mitre, status (DRAFT/DEPLOYED/…), version, test_cases |
| `incidents` | org_id, title, severity, status (OPEN…CLOSED), assigned_to, detection_source, root_cause, remediation, attack_techniques |
| `incident_timeline_entries` | incident_id, at, event_type, description, evidence refs |
| `playbooks` | org_id, name, description, status |
| `response_actions` | org_id, playbook_id, incident_id, action_type, risk_level, status, requires_approval, approved_by, executed_at |

## Platform

| Table | Key fields |
|---|---|
| `audit_logs` | org_id, actor_id, action, target_type/id, tool, result, approval, policy, ip, hash_chain |
| `agents` | org_id, name, agent_type, permissions, enabled |
| `agent_runs` | agent_id, org_id, request, output, status, created_at |
| `policies` | org_id, key, value, updated_by |
| `reports` | org_id, report_type, title, status, data (JSON), exported_at |
| `notifications` | org_id, user_id, type, title, body, read_at |

## Relationships that power the graph

```
Organization 1─* Users / Teams / Assets / Engagements / Findings /
                 Incidents / Evidence / DetectionRules / Playbooks / Reports
Asset 1─* Services, Technologies
Asset *─* Asset (asset_relationships: NETWORK_ACCESS, CAN_ACCESS, DEPENDS_ON…)
Engagement 1─* ScopeRules, Jobs, Findings
Job 1─* Scans, Findings, Evidence
Finding 1─* Remediations 1─* Retests
Incident *─* Findings (via link), 1─* TimelineEntries, ResponseActions
```

## Seed data

`python -m sentinelx.seed --force` (via `scripts/seed.sh`) creates two orgs
(Acme, Globex), users for every role, 23 assets per org (production + lab
variants), services, technologies, relationships, one approved engagement with
scope rules, jobs history, correlated findings (critical/high/medium), evidence
entries, attack paths toward the database, detection rules, incidents with
timelines, playbooks with actions, and a remediation + retest item.
