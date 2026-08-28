"""SENTINEL X API application.

REST API + WebSocket realtime + async job worker.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import Depends, FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.orm import Session

from . import __version__
from .api import admin_routes, assets_routes, auth_routes, defensive_routes, intelligence_routes, offensive_routes
from .api.deps import RequestContext, require_org
from .config import settings
from .db import get_db, init_db
from .realtime import hub

logger = logging.getLogger(__name__)

logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    tasks: list[asyncio.Task] = []
    if settings.ENVIRONMENT != "test":
        tasks.append(asyncio.create_task(_worker()))
        tasks.append(asyncio.create_task(_telemetry_watcher()))
    yield
    for task in tasks:
        task.cancel()
    for task in tasks:
        try:
            await task
        except asyncio.CancelledError:
            pass


async def _worker():
    from .services.jobs import worker_loop

    await worker_loop()


async def _telemetry_watcher():
    from .services.telemetry import telemetry_watcher

    await telemetry_watcher()


app = FastAPI(
    title="SENTINEL X API",
    version=__version__,
    description="AI-native continuous offensive and defensive security platform.",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def request_context_middleware(request: Request, call_next):
    request_id = request.headers.get("X-Request-ID") or uuid.uuid4().hex
    start = time.perf_counter()
    try:
        response = await call_next(request)
    except Exception:  # noqa: BLE001
        logger.exception("unhandled error on %s %s", request.method, request.url.path)
        response = JSONResponse(
            status_code=500,
            content={"detail": "Internal server error", "request_id": request_id},
        )
    duration_ms = round((time.perf_counter() - start) * 1000, 2)
    response.headers["X-Request-ID"] = request_id
    logger.info(
        json.dumps(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "request_id": request_id,
                "method": request.method,
                "path": request.url.path,
                "status": response.status_code,
                "duration_ms": duration_ms,
            }
        )
    )
    return response


# ---------- Health / readiness ----------

@app.get("/api/health")
def health():
    return {"status": "ok", "service": "sentinelx-api", "version": settings.API_VERSION}


@app.get("/api/ready")
def ready(db: Session = Depends(get_db)):
    try:
        db.execute(text("SELECT 1"))
        db_ok = True
    except Exception:  # noqa: BLE001
        db_ok = False
    return {"status": "ready" if db_ok else "degraded", "database": db_ok}


@app.get("/api/version")
def version():
    return {
        "version": __version__,
        "build": settings.BUILD,
        "git_revision": settings.GIT_REVISION,
        "environment": settings.ENVIRONMENT,
    }


# ---------- Command Center ----------

@app.get("/api/command-center/data")
def command_center_data(db: Session = Depends(get_db), ctx: RequestContext = Depends(require_org)):
    from .api.deps import check_permission
    from .services.dashboard import dashboard as build_dashboard

    check_permission(ctx.user, "assets:read")
    return build_dashboard(db, ctx.org.id)


# ---------- Routers ----------

for _router in [
    auth_routes.router,
    assets_routes.router,
    offensive_routes.router,
    defensive_routes.router,
    intelligence_routes.router,
    admin_routes.router,
]:
    app.include_router(_router, prefix="/api")


# ---------- WebSocket realtime ----------

@app.websocket("/ws/events")
async def ws_events(ws: WebSocket):
    await ws.accept()
    try:
        first = await asyncio.wait_for(ws.receive_text(), timeout=10)
    except (asyncio.TimeoutError, WebSocketDisconnect):
        await ws.close(code=4001)
        return
    try:
        data = json.loads(first)
        import jwt as pyjwt

        payload = pyjwt.decode(data["token"], settings.JWT_SECRET, algorithms=["HS256"])
        org_id = payload.get("org_id")
    except Exception:  # noqa: BLE001
        await ws.close(code=4001)
        return
    if not org_id:
        await ws.close(code=4001)
        return

    await hub.connect(org_id, ws)
    for msg in hub.recent(org_id, limit=30):
        try:
            await ws.send_text(json.dumps(msg))
        except Exception:  # noqa: BLE001
            break
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        await hub.disconnect(org_id, ws)
