#!/usr/bin/env bash
# =============================================================================
# SENTINEL X — stop everything (platform + lab)
#   ./scripts/stop-all.sh
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")/.."

docker compose -f cyber-range/docker-compose.lab.yml down 2>/dev/null || true
docker compose down
echo "All SENTINEL X containers stopped."
