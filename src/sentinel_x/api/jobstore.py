"""Investigation job state storage.

Two implementations:

- `InMemoryJobStore`: bounded, single-process (dev / fallback). Evicts
  oldest jobs beyond `maxsize`.
- `RedisJobStore`: survives restarts, shared across workers; entries
  carry a TTL so finished jobs clean themselves up.

Both store plain dicts: incident_id, state (running/completed/failed),
started (unix seconds), report.
"""

from __future__ import annotations

import time
from typing import Any

import structlog

logger = structlog.get_logger(__name__)

JOB_TTL_SECONDS = 24 * 3600


class JobNotFoundError(KeyError):
    pass


class InMemoryJobStore:
    """Process-local store with oldest-first eviction at maxsize."""

    def __init__(self, maxsize: int = 500):
        self._maxsize = maxsize
        self._jobs: dict[str, dict[str, Any]] = {}

    def create(self, job_id: str, incident_id: str) -> None:
        if len(self._jobs) >= self._maxsize:
            oldest = min(self._jobs, key=lambda j: self._jobs[j]["started"])
            del self._jobs[oldest]
            logger.info("job_evicted", job_id=oldest)
        self._jobs[job_id] = {
            "incident_id": incident_id,
            "state": "running",
            "started": time.time(),
            "report": None,
        }

    def get(self, job_id: str) -> dict[str, Any] | None:
        return self._jobs.get(job_id)

    def update(self, job_id: str, **fields: Any) -> None:
        if job_id not in self._jobs:
            raise JobNotFoundError(job_id)
        self._jobs[job_id].update(fields)

    def count(self) -> int:
        return len(self._jobs)


class RedisJobStore:
    """Redis-backed store; each job is a hash with a TTL."""

    def __init__(self, client):
        # redis.Redis injected to keep this testable without a live server.
        self._client = client

    @staticmethod
    def key(job_id: str) -> str:
        return f"investigation:job:{job_id}"

    def create(self, job_id: str, incident_id: str) -> None:
        mapping = {
            "incident_id": incident_id,
            "state": "running",
            "started": f"{time.time():.6f}",
            "report": "",
        }
        pipe = self._client.pipeline()
        pipe.hset(self.key(job_id), mapping=mapping)
        pipe.expire(self.key(job_id), JOB_TTL_SECONDS)
        pipe.execute()

    def get(self, job_id: str) -> dict[str, Any] | None:
        raw = self._client.hgetall(self.key(job_id))
        if not raw:
            return None
        return {
            "incident_id": raw.get("incident_id", ""),
            "state": raw.get("state", "running"),
            "started": float(raw.get("started", 0.0)),
            "report": _decode_report(raw.get("report", "")),
        }

    def update(self, job_id: str, **fields: Any) -> None:
        key = self.key(job_id)
        if not self._client.exists(key):
            raise JobNotFoundError(job_id)
        mapping: dict[str, str] = {}
        if "report" in fields:
            import json

            mapping["report"] = json.dumps(fields.pop("report")) if fields["report"] else ""
        mapping.update({k: str(v) for k, v in fields.items()})
        pipe = self._client.pipeline()
        pipe.hset(key, mapping=mapping)
        pipe.expire(key, JOB_TTL_SECONDS)
        pipe.execute()


def _decode_report(raw: str) -> dict[str, Any] | None:
    if not raw:
        return None
    import json

    try:
        return json.loads(raw)
    except ValueError:
        logger.warning("job_report_unparseable")
        return None


def choose_job_store() -> InMemoryJobStore | RedisJobStore:
    """Prefer Redis; fall back to memory when the server is unreachable."""
    from sentinel_x.common.redis_client import get_redis

    try:
        client = get_redis()
        client.ping()
        logger.info("job_store_backend", backend="redis")
        return RedisJobStore(client)
    except Exception as exc:  # noqa: BLE001 - availability probe boundary
        logger.warning("redis_unavailable_using_memory_fallback", error=str(exc))
        return InMemoryJobStore()
