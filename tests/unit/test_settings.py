"""Tests for settings loading and overrides."""

import pytest

from sentinel_x.common.settings import Settings, get_settings


def test_settings_custom_redis_url(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("REDIS_URL", "redis://:secret@custom-host:9999/2")
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("DATABASE_URL_SYNC", raising=False)
    monkeypatch.delenv("SECRET_KEY", raising=False)
    get_settings.cache_clear()
    s = Settings()
    assert s.redis_url == "redis://:secret@custom-host:9999/2"


def test_embedding_dim_default() -> None:
    s = Settings()
    assert s.embedding_dim == 384


def test_token_expire_default() -> None:
    s = Settings()
    assert s.access_token_expire_minutes == 60
