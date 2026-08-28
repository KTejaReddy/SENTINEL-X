#!/usr/bin/env bash
# Local CI runner — mirrors .github/workflows/ci.yml so every check can run on
# a developer machine before pushing. Exits non-zero on the first failure.
set -euo pipefail
cd "$(dirname "$0")/.."

ROOT="$(pwd)"
PY="${PYTHON:-python3}"
if [ -x "$ROOT/apps/api/.venv/bin/python" ]; then PY="$ROOT/apps/api/.venv/bin/python";
elif [ -x "$ROOT/apps/api/.venv/Scripts/python.exe" ]; then PY="$ROOT/apps/api/.venv/Scripts/python.exe"; fi

echo "==> [1/4] Backend unit + integration + security tests"
rm -f apps/api/test_sentinelx.db
ENVIRONMENT=test "$PY" -m pytest tests/ -q

echo "==> [2/4] Migration tests (fresh upgrade, seeding, model-vs-migration drift)"
rm -f apps/api/test_sentinelx.db
ENVIRONMENT=test "$PY" -m pytest tests/test_migrations.py -q

echo "==> [3/4] Frontend production build"
(cd apps/web && npm run build)

echo "==> [4/4] Compose stack validation"
if command -v docker >/dev/null 2>&1; then
  docker compose config --quiet && echo "root compose: OK"
  docker compose -f cyber-range/docker-compose.lab.yml config --quiet && echo "lab compose: OK"
else
  echo "docker not installed — skipping compose validation (CI will run it)"
fi

echo "==> CI green ✔"
