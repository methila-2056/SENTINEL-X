"""Shared Redis client."""

from functools import lru_cache

from redis import Redis

from sentinel_x.common.settings import get_settings


@lru_cache
def get_redis() -> Redis:
    """Process-wide Redis client bound to settings.redis_url."""
    return Redis.from_url(get_settings().redis_url, decode_responses=True)
