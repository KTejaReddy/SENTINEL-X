# SENTINEL X — Offensive operations

## Lifecycle

```
SCOPE → RECON → DISCOVERY → ENUMERATION → FINGERPRINTING → ATTACK SURFACE
→ VULNERABILITY DISCOVERY → CORRELATION → VALIDATION
→ CONTROLLED SECURITY TEST → IMPACT → EVIDENCE → FINDING
→ ATTACK PATH → REPORT → RETEST
```

The platform never hides this behind a single "HACK" button — each stage
is visible, jobs show progress and logs, and results persist as real rows.

## Engagements

States: `DRAFT → PENDING_APPROVAL → APPROVED → RUNNING ⇄ PAUSED → COMPLETED → CLOSED`

An engagement carries: authorized targets (scope rules), excluded targets,
allowed tools, the testing window, max request rate, destructive-testing
policy, data-handling policy, and approval requirements.

Recommended operating procedure:

1. Create the engagement (DRAFT).
2. Add `ALLOW` scope rules (e.g. `10.10.10.0/24`) and `DENY` rules.
3. Submit → `PENDING_APPROVAL`; an authorized approver approves.
4. Start → `RUNNING`. Run scan jobs against in-scope targets.
5. Findings land in correlation/triage; authorized validation can run.
6. Close the engagement when done; keep evidence and reports.

## Scope checks

`POST /api/engagements/{id}/check-scope` tests any target before running
anything. The scope engine resolves CIDR/hostname rules and returns
`allowed`, `reason`, and matching rule. Every job creation re-validates the
target server-side — a client cannot bypass by calling the job API directly.

## Job control

```
POST /api/jobs                      create (tool + target + params)
POST /api/jobs/{id}/cancel          stop queued or running
POST /api/jobs/{id}/pause           pause
POST /api/jobs/{id}/resume          resume
POST /api/jobs/{id}/retry           retry a failed job
GET  /api/jobs                      status, progress, logs, result
```

Jobs flow through `queued → running → completed | failed | cancelled`, with
paused as an intermediate state. Failures record the error; they are never
marked successful.

## Emergency stop

The job system provides stop-all semantics: cancel queued jobs and request
cancellation of active jobs (each adapter checks cancellation between stages).
Evidence already captured is preserved and the shutdown is written to the
audit log. The UI exposes this from the Offensive module and job controls.

## Safety rules enforced in code

- Targets outside the engagement scope → rejected (403 + reason).
- Destructive tool categories require an explicit policy grant.
- Rate limits per engagement / target / tool.
- The cyber range is internal-only; nothing in the range can reach the
  internet or the host.
- Every offensive action is audit-logged (actor, target, tool, policy,
  approval, result).

## Working with the cyber range

```bash
docker compose -f cyber-range/docker-compose.lab.yml up -d --build
docker compose -f cyber-range/docker-compose.lab.yml exec attacker bash
# targets: gateway 10.10.10.10 · web-app 10.10.10.11 · api 10.10.10.12 · db 10.10.10.13
```

Then create an engagement with scope `10.10.10.0/24` (or the specific hosts),
approve it, and run `nmap`/`nuclei`-style jobs — or use the Command Center's
controlled exercise to walk the full loop automatically.
