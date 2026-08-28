# SENTINEL X

**AI-native continuous offensive and defensive security platform.**

SENTINEL X is a business-ready security control plane for organizations that
have **explicit authorization** to assess their own systems. It combines a
complete offensive lifecycle (discover → enumerate → assess → validate →
attack path → report → retest) with an independent defensive platform
(observe → detect → investigate → respond → remediate → verify) and a
purple-team layer that measures whether your controls actually work.

> **Central promise: *continuously prove that your security controls work.***

---

## What is inside

| Capability | Status |
|---|---|
| Command Center with live WebSocket security posture | ✅ real |
| Asset inventory + attack-surface engine (23 seeded assets/org) | ✅ real |
| Engagement management with scope + rules-of-engagement engine | ✅ real |
| Tool adapter framework (nmap, nuclei, ZAP, semgrep, gitleaks, trivy, ingest, lab-range, **dast**) with graceful `NOT INSTALLED` mode | ✅ real |
| **DAST adapter** — real HTTP probes (IDOR, BOLA, BFLA, weak creds, headers) against authorized targets with response evidence | ✅ real |
| **Live lab telemetry** — cyber-range apps emit JSONL → watcher → detection → incident (no manual log copying) | ✅ real |
| **Real response actions** — account disable, token revocation, service isolation, lab patch — with measured before/after state; simulated ops are labeled `SIMULATED`, never faked as containment | ✅ real |
| Async job system (queue → worker → tool → result → WebSocket → UI) | ✅ real |
| Finding correlation + AI triage + evidence vault | ✅ real |
| Attack-path engine + interactive graph (React Flow) | ✅ real |
| SIEM event pipeline + detection engine + detection rule management | ✅ real |
| Incident management + forensic timeline + AI investigation | ✅ real |
| Response playbooks with risk-based human approval model | ✅ real |
| Purple-team coverage matrix + detection engineering loop | ✅ real |
| Remediation tracking + automated retest + security regression tests | ✅ real |
| AI Copilot with structured retrieval (no hallucinated facts) | ✅ real |
| RBAC (10 roles), multi-tenant isolation, tamper-evident audit log | ✅ real |
| Reporting (executive / pentest / purple / incident / remediation) with export | ✅ real |
| Isolated Docker cyber range with intentionally vulnerable targets (also runnable locally via `scripts/lab.sh`, no Docker) | ✅ real |
| Login rate limiting + progressive account lockout (DB-backed, audit-logged) | ✅ real |
| Alembic migration discipline — fresh-upgrade + model-vs-migration drift tests | ✅ real |
| CI pipeline (GitHub Actions + `scripts/ci.sh` + `scripts/provision-tools.sh`) | ✅ ready |
| 45 backend tests + full **security lifecycle acceptance test** (`tests/test_complete_lifecycle.py`) | ✅ passing |

**Offensive operations only run against explicitly approved targets.** Every
request passes through `engagement → scope engine → authorization check →
policy engine → tool adapter`. There is no unrestricted `AI → shell` path.

---

## Quickstart (zero dependencies beyond Python 3.10+ and Node 20+)

```bash
# 1. Bootstrap (env, backend venv, database, seed data, frontend deps)
./scripts/setup.sh

# 2. Run API + web dev servers
./scripts/dev.sh
```

Open **http://localhost:5173** and sign in:

| Role | Email | Password |
|---|---|---|
| Org Admin | `admin@acme.demo` | `SentinelX-2026!` |
| Pentester | `pentester@acme.demo` | `SentinelX-2026!` |
| SOC Analyst | `soc@acme.demo` | `SentinelX-2026!` |
| Viewer (read-only) | `viewer@acme.demo` | `SentinelX-2026!` |
| Second org (tenant isolation demo) | `admin@globex.demo` | `SentinelX-2026!` |

API docs (OpenAPI): http://127.0.0.1:8000/docs

---

## Docker Compose (full platform)

```bash
docker compose up -d --build
# web  → http://localhost:8080
# api  → http://localhost:8000/api/health
```

Postgres and Redis run with the API + worker image. OpenSearch is optional
(`docker compose --profile search up -d`).

## Controlled cyber range (isolated, intentionally vulnerable)

```bash
docker compose -f cyber-range/docker-compose.lab.yml up -d --build
./scripts/reset-lab.sh     # one-command reset
```

The range runs on an **internal** network (`10.10.10.0/24`, no outbound
internet, no published ports) with a gateway, a Flask shop app (IDOR, broken
function-level auth), a FastAPI service (BOLA/BFLA), a Postgres DB, an
authorized-testing attacker container, and a telemetry sensor. Targets:

| Host | IP | Flaws |
|---|---|---|
| gateway | 10.10.10.10 | nginx front |
| web-app | 10.10.10.11 | IDOR `/orders/<id>`, admin reachable by any user |
| api | 10.10.10.12 | BOLA `/orders/{id}`, BFLA `/admin/users`, leaked token |
| db | 10.10.10.13 | postgres, creds `app/app` |
| attacker | 10.10.10.100 | nmap / curl / python (authorized use only) |

---

## Try the full loop in the UI

From the Command Center click **RUN CONTROLLED SECURITY EXERCISE** (a labeled
demo artifact). It walks the complete lifecycle through the real pipeline:

```
approved engagement → recon job → finding → validation → attack path
→ blue-team detection → incident → response action → remediation → retest → verified
```

Each scenario is deterministic, clearly labeled `CONTROLLED LAB`, and every
step persists real rows you can inspect (jobs, events, findings, incidents,
evidence, reports).

---

## Repository layout

```
apps/
  api/        FastAPI backend (models, schemas, services, routers, worker, seed)
  web/        React + TypeScript + Vite + Tailwind frontend
tests/        backend test suite (pytest)
cyber-range/  isolated lab: vulnerable targets, attacker, monitoring
infrastructure/  Dockerfiles, nginx, postgres/redis/opensearch configs
scripts/      setup / dev / seed / test / reset-lab / stop-all
docs/         architecture, security, development, deployment, API, ops
.env.example  environment template (never commit real secrets)
```

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Security model & authorization boundary](docs/SECURITY.md)
- [Development guide](docs/DEVELOPMENT.md)
- [Deployment](docs/DEPLOYMENT.md)
- [API reference](docs/API.md)
- [Database model](docs/DATABASE.md)
- [Tool integrations](docs/TOOL-INTEGRATIONS.md)
- [AI agents & hallucination control](docs/AI-AGENTS.md)
- [Offensive operations](docs/OFFENSIVE-OPS.md)
- [Defensive operations](docs/DEFENSIVE-OPS.md)
- [Troubleshooting](docs/TROUBLESHOOTING.md)

## Tests

```bash
./scripts/test.sh
```

## License / usage note

This is a security platform for **authorized testing only**. The bundled cyber
range is deliberately isolated. You are responsible for ensuring every target
you test against is covered by an active authorization record in the
platform's engagement engine — the platform enforces this too.
