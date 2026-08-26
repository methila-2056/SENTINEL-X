"""FastAPI application factory for SENTINEL-X."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from sentinel_x.api.routers import agent, events, graph, incidents, search


def create_app() -> FastAPI:
    app = FastAPI(
        title="SENTINEL-X API",
        description="Security incident intelligence and autonomous investigation",
        version="0.1.0",
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.include_router(incidents.router, prefix="/api/incidents", tags=["incidents"])
    app.include_router(events.router, prefix="/api/events", tags=["events"])
    app.include_router(search.router, prefix="/api/knowledge", tags=["knowledge"])
    app.include_router(agent.router, prefix="/api/investigations", tags=["investigations"])
    app.include_router(graph.router, prefix="/api", tags=["graph"])

    @app.get("/api/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    return app


app = create_app()
