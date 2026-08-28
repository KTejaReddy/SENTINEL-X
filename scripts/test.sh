#!/usr/bin/env bash
# =============================================================================
# SENTINEL X — backend test suite
#   ./scripts/test.sh
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")/.."

# shellcheck disable=SC1091
source apps/api/.venv/bin/activate 2>/dev/null || source apps/api/.venv/Scripts/activate

cd apps/api
ENVIRONMENT=test python -m pytest ../tests -q
