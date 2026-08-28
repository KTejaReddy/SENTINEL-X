#!/usr/bin/env bash
# =============================================================================
# SENTINEL X — RESET LAB (one-command cyber-range reset)
#   ./scripts/reset-lab.sh
#
# Destroys and recreates the isolated cyber range from scratch.
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")/.."

echo "==> Stopping and removing the cyber range (including volumes)"
docker compose -f cyber-range/docker-compose.lab.yml down -v --remove-orphans

echo "==> Rebuilding and starting"
docker compose -f cyber-range/docker-compose.lab.yml up -d --build

echo ""
echo "Lab is back up. Verify:"
echo "    docker compose -f cyber-range/docker-compose.lab.yml ps"
echo "    docker compose -f cyber-range/docker-compose.lab.yml exec attacker bash"
