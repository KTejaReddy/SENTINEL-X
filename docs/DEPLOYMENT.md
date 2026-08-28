# SENTINEL X — Deployment

## Docker Compose (recommended for single-host)

```bash
cp .env.example .env      # set production values first!
docker compose up -d --build
```

Services: `postgres`, `redis`, `api` (REST + worker), `web` (nginx serving
the SPA and proxying `/api` + `/ws`). OpenSearch is opt-in via profile:
`docker compose --profile search up -d`.

Health: `GET /api/health` (liveness) and `GET /api/ready` (includes a DB
check). The web service depends on the API; Postgres/Redis have healthchecks
gating the API start.

## Production hardening checklist

1. **Secrets** — set `JWT_SECRET`, `ENCRYPTION_KEY`, `WEBHOOK_SECRET` to
   strong random values. The API refuses to boot with the default dev secrets
   when `ENVIRONMENT=production`.
2. **Environment** — set `ENVIRONMENT=production`, `LOG_LEVEL=INFO`.
3. **Database** — use managed PostgreSQL; run migrations on deploy
   (`alembic upgrade head`) before starting new API replicas.
4. **TLS** — terminate TLS at your ingress (nginx/traefik/ALB). The SPA
   itself is static; all state lives in the API.
5. **Replicas** — the worker is in-process. For horizontal scale-out, run
   additional API replicas behind a load balancer (Redis-backed queue/cache
   is the hook point; see `REDIS_URL`). For a separate worker fleet, run
   `python -m sentinelx.workers --count N` from the API image.
6. **Object storage** — mount `OBJECT_STORAGE_PATH` on durable storage;
   evidence must survive container restarts (use the `evidence` volume or
   S3-compatible mount).
7. **Backups** — back up Postgres and the evidence volume together; evidence
   content hashes let you verify integrity after restore.
8. **Cyber range** — never run the lab stack on the same network as the
   production stack. The lab network is `internal: true` and has no
   published ports.
9. **Logs** — JSON request logs include request IDs; ship them to your SIEM
   of choice. `audit_logs` rows are hash-chained (tamper-evident) — back them
   up off-box.

## Observability

- `GET /api/system/status` — service health + tool availability
  (`NOT INSTALLED` tools degrade gracefully, never crash the platform).
- `GET /api/system/metrics` — operational counters (jobs, events, AI
  latency, queue depth).
- Structured request logging with `X-Request-ID`.
- Ready-made hooks: OpenTelemetry/Prometheus/Grafana can scrape the
  metrics endpoint or be wired to the structured logs.

## Rolling upgrade

1. `docker compose pull` / build new images.
2. Run migrations (`docker compose run --rm api alembic upgrade head`).
3. `docker compose up -d` — new API containers drain old ones; the worker
   loop recovers queued jobs on start.
