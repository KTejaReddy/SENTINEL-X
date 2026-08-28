# SENTINEL X — API reference

Base URL: `/api` · Interactive docs: `http://127.0.0.1:8000/docs` (OpenAPI).
Auth: `Authorization: Bearer <access_token>` from `POST /auth/login`.

WebSocket realtime: `ws://127.0.0.1:8000/ws/events` — first message must be
`{"token": "<access_token>"}`. Events are org-scoped and include a replay
buffer of the last 30 events on connect.

## Health / meta

| Method | Path | Notes |
|---|---|---|
| GET | `/api/health` | liveness |
| GET | `/api/ready` | readiness incl. DB check |
| GET | `/api/version` | version, build, env |
| GET | `/api/command-center/data` | dashboard payload (posture, live feeds) |

## Auth & orgs (`auth_routes`)

| Method | Path | Notes |
|---|---|---|
| POST | `/api/auth/login` | `{email, password}` → `{access_token, refresh_token, user}` |
| POST | `/api/auth/refresh` | rotate refresh token |
| POST | `/api/auth/logout` | revoke refresh family |
| GET | `/api/auth/me` | current user |
| POST | `/api/organizations` | create org (SUPER_ADMIN) |
| GET | `/api/organizations` | list orgs |
| POST | `/api/users` | create user in org |
| GET | `/api/users` | list org users |
| PATCH | `/api/users/{id}` | update role / status |

## Assets (`assets_routes`)

| Method | Path | Notes |
|---|---|---|
| GET/POST | `/api/assets` | list / create |
| GET/PATCH | `/api/assets/{id}` | read / update |
| GET | `/api/assets/{id}/services` | services on asset |
| GET/POST | `/api/assets/{id}/relationships` | asset graph edges |
| GET | `/api/attack-surface` | exposure summary + changes |

## Offensive (`offensive_routes`)

| Method | Path | Notes |
|---|---|---|
| GET/POST | `/api/engagements` | list / create |
| GET | `/api/engagements/{id}` | detail |
| POST | `/api/engagements/{id}/scope` | add scope rules (CIDR/hostname) |
| POST | `/api/engagements/{id}/submit` | DRAFT → PENDING_APPROVAL |
| POST | `/api/engagements/{id}/approve` | PENDING_APPROVAL → APPROVED |
| POST | `/api/engagements/{id}/start` | APPROVED → RUNNING |
| POST | `/api/engagements/{id}/pause` | RUNNING → PAUSED |
| POST | `/api/engagements/{id}/close` | → CLOSED |
| POST | `/api/engagements/{id}/check-scope` | test a target against rules |
| GET/POST | `/api/jobs` | list / create (`{tool, target, params}`) |
| POST | `/api/jobs/{id}/cancel` | cancel queued/running |
| POST | `/api/jobs/{id}/pause` | pause |
| POST | `/api/jobs/{id}/resume` | resume |
| POST | `/api/jobs/{id}/retry` | retry failed |
| GET | `/api/tools` | registry with availability |
| POST | `/api/tools/health-check` | probe adapter health |
| GET/POST | `/api/findings` | list / create |
| GET/PATCH | `/api/findings/{id}` | detail / update status |
| POST | `/api/findings/{id}/validate` | run authorized validation |
| GET | `/api/vulnerabilities` | deduplicated vulnerability view |
| GET/POST | `/api/evidence` | evidence vault |
| GET | `/api/evidence/{id}` | evidence detail |
| POST | `/api/remediation` | create remediation item |
| GET | `/api/remediation` | list |
| POST | `/api/remediation/{id}/verify` | verify fix (links retest) |
| GET | `/api/retests` | retest history |

## Defensive (`defensive_routes`)

| Method | Path | Notes |
|---|---|---|
| GET/POST | `/api/events` | query / ingest normalized events |
| GET | `/api/events/feed` | realtime-ish feed |
| GET/POST | `/api/detections/rules` | detection rules |
| PATCH | `/api/detections/rules/{id}` | update/version rule |
| GET/POST | `/api/incidents` | list / create |
| GET/PATCH | `/api/incidents/{id}` | detail / update |
| GET/POST | `/api/incidents/{id}/timeline` | forensic timeline |
| POST | `/api/incidents/{id}/analyze` | AI investigation (structured) |
| POST | `/api/incidents/{id}/link-finding` | correlate vulnerability |
| POST | `/api/hunts` | natural-language hunt → validated query plan |
| GET/POST | `/api/playbooks` | response playbooks |
| POST | `/api/playbooks/{id}/actions` | add action |
| GET | `/api/responses/actions` | all actions |
| POST | `/api/responses/actions/{id}/approve` | approve (HIGH/CRITICAL) |
| POST | `/api/responses/actions/{id}/execute` | run via adapter |

## Intelligence (`intelligence_routes`)

| Method | Path | Notes |
|---|---|---|
| GET | `/api/attack-paths` | list paths |
| POST | `/api/attack-paths/compute` | recompute paths |
| GET | `/api/attack-graph` | graph payload for React Flow |
| GET | `/api/purple/coverage` | ATT&CK-stage coverage matrix |
| POST | `/api/purple/exercise` | run purple exercise |
| GET | `/api/purple/results` | exercise results |
| GET | `/api/reports` | list reports |
| POST | `/api/reports/generate` | generate (exec/pentest/purple/incident/remediation) |
| GET | `/api/reports/{id}` | detail |
| GET | `/api/reports/{id}/export` | JSON export (PDF/MD via report service) |
| POST | `/api/ai/triage` | AI finding triage (typed output) |
| POST | `/api/ai/action` | structured AI action request (scope+policy gated) |
| POST | `/api/ai/copilot` | org-aware copilot Q&A |
| POST | `/api/ai/exercise` | controlled security exercise |

## Admin (`admin_routes`)

| Method | Path | Notes |
|---|---|---|
| GET | `/api/audit` | tamper-evident audit log |
| GET | `/api/notifications` | org notifications |
| POST | `/api/notifications/{id}/read` | mark read |
| GET | `/api/policies` | policy engine config |
| GET | `/api/agents` | AI agent registry |
| GET | `/api/agents/{id}/runs` | agent run history |
| GET | `/api/search` | global search (assets/findings/incidents/…) |
| GET | `/api/system/status` | health + tool availability |
| GET | `/api/system/metrics` | operational metrics |
| GET | `/api/organizations/current` | current org |

## Error handling

- Structured `{"detail": "..."}` bodies; request IDs on every response
  (`X-Request-ID`).
- 401 unauthenticated · 403 unauthorized (missing permission or out of
  scope) · 404 not found (org-scoped) · 422 validation · 500 with request ID.
- Out-of-scope offensive targets return 403 with a structured
  `reason` from the scope engine.
