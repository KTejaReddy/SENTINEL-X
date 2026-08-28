#!/usr/bin/env bash
# =============================================================================
# SENTINEL X — run API + web dev servers
#   ./scripts/dev.sh
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")/.."

# shellcheck disable=SC1091
source apps/api/.venv/bin/activate 2>/dev/null || source apps/api/.venv/Scripts/activate

trap 'kill 0' EXIT

(cd apps/api && uvicorn sentinelx.main:app --host 127.0.0.1 --port 8000) &
(cd apps/web && npm run dev) &

echo "API  : http://127.0.0.1:8000/api/health  (docs at /docs)"
echo "Web  : http://127.0.0.1:5173"
echo "Login: admin@acme.demo / SentinelX-2026!"
wait
