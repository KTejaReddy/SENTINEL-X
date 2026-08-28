# SENTINEL X — Security model

This document describes the platform's own security architecture: how it
protects tenants, how it authorizes offensive operations, and how it keeps
evidence trustworthy.

## 1. The offensive authorization boundary (non-negotiable)

Every offensive operation must pass through:

```
USER / AI INTENT
      → ENGAGEMENT
      → SCOPE ENGINE
      → AUTHORIZATION CHECK
      → POLICY ENGINE
      → TOOL ADAPTER
      → SANDBOX / AUTHORIZED TARGET
      → RESULT
```

Enforced in code:

- **ScopeEngine** (`services/scope_engine.py`) — CIDR/hostname rules are
  resolved against the engagement's `scope_rules`. Targets must match an
  `ALLOW` rule and must not match any `DENY` rule. Non-matching targets are
  rejected with a structured reason (`outside_scope`, `denied_by_rule`).
- **Engagement authorization** — an engagement must be `APPROVED`, within its
  testing window, and the tool must be in its allowed tool set. Per-target and
  per-engagement rate limits are enforced.
- **PolicyEngine** (`services/policy_engine.py`) — tool categories
  (`discovery`, `vulnerability_scan`, `exploitation`, `destructive`) map to
  policy decisions. Destructive tools require an explicit policy grant;
  otherwise the request is rejected.
- **ToolAdapter** — adapters receive structured requests only. There is no
  endpoint that accepts an arbitrary CLI command string from the client or
  from the AI. Each adapter builds its own constrained command line and
  normalizes output.

The **AI can never target an arbitrary Internet host**: its structured
`ai/action` requests are validated against the same scope + policy engines
before a job is created.

## 2. Multi-tenancy

Every tenant-owned table carries `org_id`. The tenant context is derived
server-side from the authenticated JWT (`require_org` dependency) — a
tenant ID supplied by the frontend is never trusted. All list/create/update
queries filter by `ctx.org.id`. Tests cover tenant isolation: org A users
cannot read org B assets, findings, or incidents.

## 3. Authentication

- Passwords hashed with **bcrypt** (`security/auth.py`).
- JWT access tokens (short-lived, default 30 min) + rotating refresh tokens
  stored hashed in `refresh_tokens`; logout revokes the family.
- Login/logout/refresh events are written to `audit_logs`.
- The auth design is MFA-ready: a `mfa_enabled` flag and `mfa_secret` field
  exist on the user model; the login flow is structured to accept a
  second factor without refactoring.

## 4. RBAC

Ten roles with permission sets in `security/rbac.py`:

`SUPER_ADMIN, ORG_ADMIN, CISO, SECURITY_ADMIN, PENTESTER, SOC_ANALYST,
SECURITY_ENGINEER, DEVELOPER, AUDITOR, VIEWER`

Permissions are checked in the API layer (`check_permission`), not merely
hidden in the UI. Examples: `assets:read`, `assets:write`, `engagements:write`,
`engagements:approve`, `jobs:run`, `incidents:write`, `responses:execute`,
`audit:read`. Approving an engagement and executing a HIGH/CRITICAL response
action are distinct, more restricted permissions.

## 5. Human approval model for response actions

Every playbook action carries a `risk_level` (`LOW|MEDIUM|HIGH|CRITICAL`).
The policy engine decides whether approval is required:

| Risk | Example | Approval |
|---|---|---|
| LOW | create ticket | automatic |
| MEDIUM | enable enhanced monitoring | automatic |
| HIGH | disable test account | required |
| CRITICAL | production isolation | required, explicit |

`POST /responses/actions/{id}/approve` records the approver, then
`POST /responses/actions/{id}/execute` runs the action through the response
adapter. Both transitions are audited.

## 6. Evidence vault

- Evidence rows store `content_hash` (SHA-256) and an immutable-style
  `audit_history` (append-only JSON), so a captured artifact cannot be
  silently altered without detection.
- Evidence types: screenshot, scanner_result, http_evidence, log, alert,
  report_attachment.
- Every evidence row links to its source job/finding/incident and the org.

## 7. Audit logging

`audit_logs` captures `actor_id, org_id, action, target_type, target_id,
tool, result, approval, policy, ip, user_agent, hash_chain`. The `hash_chain`
links each row to the previous row's hash, making the log tamper-evident
(any modification breaks the chain). Audit is tenant-isolated; `AUDITOR` and
`SUPER_ADMIN`/`ORG_ADMIN` can read it.

## 8. Secrets & configuration

- No credentials live in source. `.env.example` documents every variable.
- Production startup validation rejects default secrets
  (`JWT_SECRET`, `ENCRYPTION_KEY`, `WEBHOOK_SECRET`) — the API refuses to boot.
- AI provider keys come from the environment (`AI_API_KEY`), never from the
  database or the client.

## 9. Safety controls

- `POST /jobs/{id}/cancel|pause|resume|retry` for full lifecycle control.
- Global emergency stop is exposed via the job system (cancel queued,
  mark active for cancellation) and documented in
  [Offensive operations](OFFENSIVE-OPS.md).
- Rate limits per engagement/target/tool, enforced in the scope engine.
- The cyber range is on an internal-only Docker network with no published
  ports — it cannot reach the internet or the host.

## 10. AI hallucination control

See [AI agents](AI-AGENTS.md): AI output is always validated against strict
Pydantic schemas; unsupported actions and out-of-scope targets are rejected;
missing evidence yields `INSUFFICIENT EVIDENCE` rather than a fabricated
conclusion.
