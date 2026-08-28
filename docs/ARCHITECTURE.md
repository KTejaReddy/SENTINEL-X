# SENTINEL X — Architecture

## System overview

```
┌─────────────────────────────── WEB (React + Vite + Tailwind) ───────────────┐
│  Command Center · Assets · Attack Surface · Offensive · Vulnerabilities ·   │
│  Attack Paths (React Flow) · SOC · Incidents · Hunting · Detection ·        │
│  Response · Purple Team · Remediation · Reports · AI Copilot · Admin        │
└───────────────┬─────────────────────────────────────────────┬───────────────┘
                │ REST (/api/*)                               │ WebSocket (/ws/events)
┌───────────────▼─────────────────────────────────────────────▼───────────────┐
│                              FASTAPI APP                                     │
│  auth / RBAC / tenant-scoping middleware                                     │
│  routers: auth, assets, offensive, defensive, intelligence, admin            │
│  WebSocket hub → tenant-scoped realtime event stream                         │
└───────┬─────────────────────┬───────────────────────────┬───────────────────┘
        │                     │                           │
┌───────▼─────────┐  ┌────────▼──────────┐  ┌─────────────▼──────────────┐
│ SERVICE LAYER   │  │ JOB SYSTEM        │  │ INTEGRATION LAYER           │
│ scope_engine    │  │ queue → worker    │  │ ToolAdapter base            │
│ policy_engine   │  │ pause/cancel/     │  │ nmap · nuclei · zap ·       │
│ risk engine     │  │ retry/dead-letter │  │ semgrep · gitleaks · trivy  │
│ attack_paths    │  │ WebSocket events  │  │ ingest · lab-range          │
│ correlation     │  │                   │  │ every tool → normalized     │
│ evidence vault  │  │                   │  │ entities, never raw CLI     │
│ detection       │  │                   │  │ missing tool = NOT INSTALLED│
│ incidents       │  │                   │  └─────────────────────────────┘
│ purple/retest   │  │                   │
│ ai (triage,     │  │                   │
│  copilot,       │  └───────────────────┘
│  incident)      │
└─────────────────┴───────────────────────────────────────────────────────────┘
        │                           │
┌───────▼───────────────────────────▼─────────────────────────────────────────┐
│ DATA: PostgreSQL (primary) · SQLite (zero-dependency local default)         │
│       Redis optional (queue/cache) · OpenSearch optional (event search)     │
│       filesystem evidence vault (content-hashed, append-only)               │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Execution flow — offensive

```
USER / AI intent
      → Engagement (status APPROVED)
      → ScopeEngine.check_target(engagement, target)
      → Authorization check (active window, allowed tools, rate limits)
      → PolicyEngine (destructive? approval required? category allowed?)
      → ToolAdapter (build_request → execute → parse → normalize)
      → Job row persists status/progress/result
      → WebSocket event → UI
```

Every step is recorded in `audit_logs`. Jobs can be paused, cancelled, resumed,
and retried. Failed jobs are never marked successful.

## Execution flow — defensive

```
Sensor / ingest adapter → Event (normalized schema)
      → DetectionEngine (signature rules + correlation + thresholds)
      → Incident created with timeline
      → Response playbook actions (risk-ranked, approval-gated)
      → Remediation → Retest → Verified
```

## Execution flow — purple

```
Controlled exercise (approved engagement, lab targets)
      → red activity (real jobs) + expected telemetry
      → actual telemetry compared
      → detection gap → rule proposal → deploy → replay → verified
      → coverage matrix updated + security regression test recorded
```

## Realtime

The API runs an in-process WebSocket hub. Any service can publish
tenant-scoped events (`job_queued`, `job_started`, `event_ingested`,
`incident_created`, `detection_hit`, …) that are streamed to connected clients.
The hub keeps a small recency buffer so a page reload replays the last events.
`realtime.publish_sync` works from the async worker loop and from sync contexts.

## Concurrency & failure handling

- Async worker loop polls queued jobs, runs adapters with timeouts.
- Retries with backoff on transient failures; dead-letter state for poison jobs.
- All-or-nothing state transitions (`queued → running → completed/failed`).
- Request IDs on every API response; structured JSON request logging.
- Startup configuration validation — the app refuses to boot with insecure
  secrets in production.

## Module map

| Layer | Location |
|---|---|
| Models (32 tables) | `apps/api/sentinelx/models/` |
| Pydantic schemas | `apps/api/sentinelx/schemas/` |
| Security (auth, RBAC, crypto, audit) | `apps/api/sentinelx/security/` |
| Services | `apps/api/sentinelx/services/` |
| Tool adapters | `apps/api/sentinelx/integrations/` |
| API routers | `apps/api/sentinelx/api/` |
| Seed / demo data | `apps/api/sentinelx/seed.py` |
| Worker entrypoint | `apps/api/sentinelx/workers/` |
| Frontend | `apps/web/src/` |
