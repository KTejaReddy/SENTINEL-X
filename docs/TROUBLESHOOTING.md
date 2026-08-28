# SENTINEL X — Troubleshooting

## API won't start

| Symptom | Fix |
|---|---|
| `FATAL: missing/insecure configuration` | You set `ENVIRONMENT=production` but kept dev secrets. Set strong `JWT_SECRET`/`ENCRYPTION_KEY`/`WEBHOOK_SECRET` in `.env`. |
| `sqlalchemy.exc.OperationalError` | DB not reachable. SQLite: check `apps/api/` cwd and write perms. Postgres: confirm `DATABASE_URL`, run `docker compose ps`. |
| Port 8000 already in use | `netstat -ano | grep 8000` on Windows, `lsof -i :8000` on macOS/Linux; kill the process or change the port. |

## Frontend issues

| Symptom | Fix |
|---|---|
| Blank page / API 401 loop | `.env` `JWT_SECRET` changed after login — the API rejects old tokens. Restart API, log out, log in. |
| Realtime feed empty | Check `REALTIME LIVE` indicator in the header. Verify WS connects: browser devtools → Network → WS. The endpoint requires the token in the first frame. |
| `npm run build` type errors | `cd apps/web && npm run build` — fix reported types. |
| CORS errors | `CORS_ORIGINS` must include the frontend origin (default `http://localhost:5173`). |

## Offensive jobs fail

| Symptom | Fix |
|---|---|
| Job fails `tool not installed` | The adapter reported `NOT INSTALLED`. Install the tool (e.g. `apt install nmap`) or use the `lab-range` adapter for the demo. |
| 403 out of scope | The target isn't covered by an `ALLOW` rule of an approved, in-window engagement. Add scope rules / approve / start the engagement. |
| Job stuck `queued` | The worker loop isn't running. If `ENVIRONMENT=test` it's disabled; otherwise check API logs. Run a standalone worker: `python -m sentinelx.workers`. |
| Job stuck `running` | Pause/cancel it from the Offensive module, then retry. |

## Cyber range

| Symptom | Fix |
|---|---|
| Lab containers can't reach the internet | By design — the lab network is `internal: true`. |
| `web-app`/`api` restart loop | They wait ~1s for the DB; if Postgres is slow, `docker compose -f cyber-range/docker-compose.lab.yml restart db web-app api`. |
| Lab reset needed | `./scripts/reset-lab.sh` (down -v + up --build). |
| Port conflicts with platform stack | Lab services publish no host ports, so they can't conflict. |

## Re-seeding

```bash
./scripts/seed.sh          # wipes sentinelx.db, migrates, reseeds
```

This only touches the local SQLite dev DB.

## Everything else

- API logs are JSON with request IDs; grep them for the failing request ID.
- `GET /api/system/status` shows service + tool health at a glance.
- Open an issue with: request ID, API log lines, the failing endpoint, and
  your `.env` keys *redacted* (never share secrets).
