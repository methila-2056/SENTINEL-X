"""Deep health check endpoint with dependency probes.

GET /api/health/deep returns per-component status (Postgres, Redis)
and the overall status.  Used by monitoring dashboards; the lightweight
GET /api/health (in app.py) remains for Docker healthchecks.
"""

from __future__ import annotations

import time

import structlog
from fastapi import APIRouter
from sqlalchemy import text

router = APIRouter()
logger = structlog.get_logger(__name__)


def _check_postgres() -> dict:
    from sentinel_x.common.db import get_sync_session

    start = time.monotonic()
    try:
        with get_sync_session() as session:
            session.execute(text("SELECT 1"))
        ms = round((time.monotonic() - start) * 1000, 1)
        return {"status": "ok", "latency_ms": ms}
    except Exception as exc:  # noqa: BLE001
        ms = round((time.monotonic() - start) * 1000, 1)
        logger.warning("health_postgres_fail", error=str(exc))
        return {"status": "error", "error": str(exc), "latency_ms": ms}


def _check_redis() -> dict:
    from sentinel_x.common.redis_client import get_redis

    start = time.monotonic()
    try:
        r = get_redis()
        r.ping()
        ms = round((time.monotonic() - start) * 1000, 1)
        return {"status": "ok", "latency_ms": ms}
    except Exception as exc:  # noqa: BLE001
        ms = round((time.monotonic() - start) * 1000, 1)
        logger.warning("health_redis_fail", error=str(exc))
        return {"status": "error", "error": str(exc), "latency_ms": ms}


@router.get("/health/deep")
def health_deep() -> dict:
    """Deep health check probing PostgreSQL and Redis."""
    components = {
        "postgres": _check_postgres(),
        "redis": _check_redis(),
    }
    overall = "ok" if all(c["status"] == "ok" for c in components.values()) else "degraded"
    return {"status": overall, "components": components}
