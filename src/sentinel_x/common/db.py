"""Database engines and session factories."""

from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from sentinel_x.common.settings import get_settings


def get_sync_engine():
    settings = get_settings()
    return create_engine(settings.database_url_sync, pool_pre_ping=True)


def get_async_engine():
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    settings = get_settings()
    engine = create_async_engine(settings.database_url, pool_pre_ping=True)
    return engine, async_sessionmaker(engine, expire_on_commit=False)


def get_sync_session() -> Session:
    factory = sessionmaker(bind=get_sync_engine(), expire_on_commit=False)
    return factory()


def ensure_vector_extension(engine) -> None:
    """CREATE EXTENSION IF NOT EXISTS vector (idempotent bootstrap)."""
    from sqlalchemy import text

    with engine.begin() as conn:
        conn.execute(text("CREATE EXTENSION IF NOT EXISTS vector"))


def create_all() -> None:
    """Create all tables (bootstrap for dev; Alembic migrations later)."""
    import sentinel_x.data.db.models  # noqa: F401 - register mappers

    engine = get_sync_engine()
    ensure_vector_extension(engine)
    from sentinel_x.data.db.models import Base

    Base.metadata.create_all(engine)
    print("Database schema created")


if __name__ == "__main__":  # direct execution convenience
    create_all()
    _ = Path(__file__)
