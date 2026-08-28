#!/usr/bin/env bash
# Start the cyber-range lab targets as local processes (no Docker required).
#
#   lab-web  : http://127.0.0.1:5000   (intentionally vulnerable Flask shop)
#   lab-api  : http://127.0.0.1:9002   (intentionally vulnerable FastAPI)
#
# The lab apps emit JSONL telemetry into cyber-range/logs/, which the SENTINEL X
# API's telemetry watcher tails and pushes through the detection pipeline.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$(pwd)"
PY="$ROOT/apps/api/.venv/Scripts/python.exe"
[ -x "$PY" ] || PY="$ROOT/apps/api/.venv/bin/python"

mkdir -p cyber-range/logs

# Restart any existing lab processes
for port in 5000 9002; do
  pid=$(netstat -ano 2>/dev/null | grep ":$port" | grep LISTENING | awk '{print $5}' | head -1 || true)
  [ -n "${pid:-}" ] && kill "$pid" 2>/dev/null || true
done

cd "$ROOT/cyber-range/targets/web-app"
LAB_EVENT_LOG="$ROOT/cyber-range/logs/lab-web.jsonl" "$PY" app.py > /tmp/lab-web.log 2>&1 &

cd "$ROOT/cyber-range/targets/api"
LAB_API_EVENT_LOG="$ROOT/cyber-range/logs/lab-api.jsonl" "$PY" -m uvicorn main:app --host 127.0.0.1 --port 9002 > /tmp/lab-api.log 2>&1 &

sleep 4
curl -sf http://127.0.0.1:5000/healthz >/dev/null && echo "lab-web  : http://127.0.0.1:5000  (up)"
curl -sf http://127.0.0.1:9002/healthz >/dev/null && echo "lab-api  : http://127.0.0.1:9002  (up)"
echo "Telemetry logs: $ROOT/cyber-range/logs/"
echo "Run the lifecycle test:  python -m pytest tests/test_complete_lifecycle.py"
