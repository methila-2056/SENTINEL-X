"""Unit tests for core package bootstrap."""

from sentinel_x import __version__
from sentinel_x.common.logging import get_logger
from sentinel_x.common.settings import Settings


def test_version() -> None:
    assert __version__ == "0.1.0"


def test_settings_defaults() -> None:
    settings = Settings()
    assert settings.database_url.startswith("postgresql+asyncpg://")
    assert settings.embedding_model == "sentence-transformers/all-MiniLM-L6-v2"
    assert settings.ollama_base_url == "http://localhost:11434"


def test_secret_key_is_masked() -> None:
    settings = Settings()
    assert "change-me" not in repr(settings.secret_key)


def test_get_logger() -> None:
    log = get_logger("test")
    assert log is not None
