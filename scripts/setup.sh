#!/usr/bin/env bash
# =============================================================================
# SENTINEL X — local bootstrap
#
#   ./scripts/setup.sh
#
# Creates .env, installs backend deps into a venv, creates the database,
# seeds demo data, and installs frontend deps. Run ./scripts/dev.sh afterwards.
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")/.."

echo "==> 1/4 Environment"
if [ ! -f .env ]; then
  cp .env.example .env
  echo "    created .env from .env.example"
fi

echo "==> 2/4 Backend"
python3 -m venv apps/api/.venv 2>/dev/null || python -m venv apps/api/.venv
# shellcheck disable=SC1091
source apps/api/.venv/bin/activate 2>/dev/null || source apps/api/.venv/Scripts/activate
pip install -q -r apps/api/requirements.txt

echo "==> 3/4 Database (SQLite by default; see DATABASE_URL for Postgres)"
cd apps/api
rm -f sentinelx.db
alembic upgrade head
python -m sentinelx.seed
cd ..

echo "==> 4/4 Frontend"
cd apps/web
npm install --no-audit --no-fund
cd ..

echo ""
echo "Setup complete. Start with:"
echo "    ./scripts/dev.sh"
echo "    http://localhost:5173  (admin@acme.demo / SentinelX-2026!)"
