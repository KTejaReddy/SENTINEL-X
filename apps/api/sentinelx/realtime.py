"""In-memory WebSocket hub for org-scoped realtime events.

Events published by services (jobs, findings, incidents, detections, events)
are pushed to connected clients that belong to the same organization.
"""
from __future__ import annotations

import asyncio
import json
import logging
import uuid
from collections import defaultdict
from typing import Any

from fastapi import WebSocket

logger = logging.getLogger(__name__)


def fire_and_forget(coro):
    """Schedule a coroutine, safely in both async and sync contexts."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None
    if loop is not None:
        loop.create_task(coro)
    else:
        try:
            asyncio.run(coro)
        except Exception:  # noqa: BLE001
            logger.exception("realtime publish failed")


class Hub:
    def __init__(self) -> None:
        self._connections: dict[str, set[WebSocket]] = defaultdict(set)
        self._lock = asyncio.Lock()
        self._recent: list[dict[str, Any]] = []  # ring buffer for late joiners

    async def connect(self, org_id: str, ws: WebSocket) -> None:
        """Register a client. The endpoint is responsible for accepting first."""
        async with self._lock:
            self._connections[org_id].add(ws)

    async def disconnect(self, org_id: str, ws: WebSocket) -> None:
        async with self._lock:
            self._connections[org_id].discard(ws)

    async def publish(self, org_id: str, event_type: str, payload: dict[str, Any]) -> None:
        message = {
            "id": uuid.uuid4().hex,
            "type": event_type,
            "org_id": org_id,
            "payload": payload,
            "ts": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
        }
        self._recent.append(message)
        if len(self._recent) > 500:
            self._recent = self._recent[-500:]
        async with self._lock:
            targets = list(self._connections.get(org_id, set()))
        dead: list[WebSocket] = []
        for ws in targets:
            try:
                await ws.send_text(json.dumps(message))
            except Exception:
                dead.append(ws)
        for ws in dead:
            await self.disconnect(org_id, ws)

    def publish_sync(self, org_id: str, event_type: str, payload: dict[str, Any]) -> None:
        fire_and_forget(self.publish(org_id, event_type, payload))

    def recent(self, org_id: str, limit: int = 50) -> list[dict[str, Any]]:
        return [m for m in self._recent if m.get("org_id") == org_id][-limit:]


hub = Hub()
