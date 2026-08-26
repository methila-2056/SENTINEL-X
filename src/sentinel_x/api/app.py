"""FastAPI application factory for SENTINEL-X."""

from __future__ import annotations

from contextlib import asynccontextmanager

import structlog
from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import func, select

from sentinel_x.api.audit import AuditLogMiddleware
from sentinel_x.api.deps import get_current_user
from sentinel_x.api.ratelimit import RateLimitMiddleware
from sentinel_x.api.routers import agent, events, graph, incidents, search
from sentinel_x.api.routers.health import router as health_router

logger = structlog.get_logger(__name__)


@asynccontextmanager
async def _lifespan(app: FastAPI):
    from sentinel_x.common.db import get_sync_session
    from sentinel_x.common.settings import get_settings
    from sentinel_x.data.db.models import UserRow

    secret = get_settings().secret_key.get_secret_value()
    if len(secret) < 32:
        logger.warning("weak_jwt_secret", hint="set SECRET_KEY (>= 32 bytes) in production")
    with get_sync_session() as session:
        n_users = session.scalar(select(func.count(UserRow.id)))
    if not n_users:
        logger.warning(
            "no_api_users",
            hint="create an account with: python scripts/create_user.py "
            "--username admin --password ... --role admin",
        )
    yield


def create_app() -> FastAPI:
    app = FastAPI(
        title="SENTINEL-X API",
        description=(
            "Security incident intelligence and autonomous investigation. "
            "Authenticated with bearer JWTs obtained from /api/auth/token."
        ),
        version="0.1.0",
        lifespan=_lifespan,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.add_middleware(AuditLogMiddleware)
    app.add_middleware(RateLimitMiddleware)

    # Mutating endpoints additionally require elevated roles.
    app.include_router(
        incidents.router,
        prefix="/api/incidents",
        tags=["incidents"],
        dependencies=[Depends(get_current_user)],
    )
    app.include_router(
        events.router,
        prefix="/api/events",
        tags=["events"],
        dependencies=[Depends(get_current_user)],
    )
    app.include_router(
        search.router,
        prefix="/api/knowledge",
        tags=["knowledge"],
        dependencies=[Depends(get_current_user)],
    )
    app.include_router(
        agent.router,
        prefix="/api/investigations",
        tags=["investigations"],
        dependencies=[Depends(get_current_user)],
    )
    app.include_router(
        graph.router,
        prefix="/api",
        tags=["graph"],
        dependencies=[Depends(get_current_user)],
    )

    from sentinel_x.api.routers import auth

    # /api/auth/token is public; the remaining auth endpoints carry their own
    # role requirements.
    app.include_router(auth.router, prefix="/api/auth", tags=["auth"])

    @app.get("/api/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    # Deep health probes (no auth required; exempt from rate limiting)
    app.include_router(health_router, prefix="/api", tags=["health"])

    return app


app = create_app()
