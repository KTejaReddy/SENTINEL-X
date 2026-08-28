"""LAB telemetry sensor.

Polls the lab targets and emits normalized JSON event lines (the same shape
the SENTINEL X defensive pipeline ingests). Target map and interval are
configurable via environment so the sensor runs against the docker network
(10.10.10.x) or a local lab (127.0.0.1).

Lines are written to stdout AND to a JSONL file that the platform's
telemetry watcher tails — no manual log copying required.
"""
import json
import os
import time
import urllib.request
from pathlib import Path

DEFAULT_TARGETS = {
    "lab-gateway": "http://10.10.10.10/healthz",
    "lab-web": "http://10.10.10.11/healthz",
    "lab-api": "http://10.10.10.12/healthz",
    "lab-db": "http://10.10.10.13:5432",
}

TARGETS = json.loads(os.environ.get("SENSOR_TARGETS") or json.dumps(DEFAULT_TARGETS))
INTERVAL = float(os.environ.get("SENSOR_INTERVAL", "10"))
LOG_PATH = Path(os.environ.get("SENSOR_LOG_PATH", Path(__file__).resolve().parents[1] / "logs" / "sensor.jsonl"))
LOG_PATH.parent.mkdir(parents=True, exist_ok=True)


def probe(name: str, url: str) -> dict:
    t0 = time.time()
    try:
        with urllib.request.urlopen(url, timeout=3) as resp:
            ok = resp.status < 400
            latency_ms = round((time.time() - t0) * 1000, 1)
            return {"asset": name, "ok": ok, "latency_ms": latency_ms, "status": resp.status}
    except Exception as exc:  # noqa: BLE001
        return {"asset": name, "ok": False, "latency_ms": None, "status": str(exc)}


def emit(event_type: str, severity: str, source: str, message: str, meta: dict | None = None) -> None:
    line = json.dumps(
        {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "source": source,
            "event_type": event_type,
            "severity": severity,
            "message": message,
            "meta": meta or {},
        }
    )
    print(line, flush=True)
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(line + "\n")


def main() -> None:
    emit("monitoring:started", "low", "lab-monitoring", "lab sensor online", {"targets": list(TARGETS.keys())})
    while True:
        for name, url in TARGETS.items():
            result = probe(name, url)
            if not result["ok"]:
                emit("asset:unreachable", "medium", "lab-monitoring", f"{name} {result['status']}", {"asset": name})
            else:
                emit("asset:heartbeat", "low", "lab-monitoring", f"{name} ok latency={result['latency_ms']}ms", {"asset": name, "latency_ms": result["latency_ms"]})
        time.sleep(INTERVAL)


if __name__ == "__main__":
    main()
