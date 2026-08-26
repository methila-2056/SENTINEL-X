"""Integration tests for the Redis-backed job store.

Requires a reachable Redis; REDIS_URL is honored (CI provisions a service
container, locally `docker compose up -d redis` exposes 6380).
"""

import json
import os

import pytest

from sentinel_x.api.jobstore import JOB_TTL_SECONDS, JobNotFoundError, RedisJobStore

redis = pytest.importorskip("redis", reason="redis-py not installed")

# TEST_REDIS_URL wins; then REDIS_URL (set by CI service containers and
# local .env alike); db /15 keeps test data isolated.
REDIS_URL = (
    os.environ.get("TEST_REDIS_URL") or os.environ.get("REDIS_URL") or "redis://localhost:6380/15"
)
if REDIS_URL.rstrip("/")[-1:] == "/" or REDIS_URL.endswith("/0"):
    # Never flush a shared default DB - force an isolated one for tests.
    REDIS_URL = f"{REDIS_URL.rsplit('/', 1)[0]}/15"


@pytest.fixture()
def store():
    client = redis.Redis.from_url(REDIS_URL, decode_responses=True)
    try:
        client.ping()
    except redis.exceptions.ConnectionError as exc:
        pytest.skip(f"Redis unreachable at {REDIS_URL}: {exc}")
    client.flushdb()
    yield RedisJobStore(client)
    client.flushdb()


def test_create_get_lifecycle(store: RedisJobStore) -> None:
    store.create("job-1", "det-0002")
    job = store.get("job-1")
    assert job == {
        "incident_id": "det-0002",
        "state": "running",
        "started": pytest.approx(job["started"], abs=5),
        "report": None,
    }


def test_update_report_and_state(store: RedisJobStore) -> None:
    report = {"summary": "phishing confirmed", "evidence_ids": ["EV-1"]}
    store.create("job-2", "det-0003")
    store.update("job-2", state="completed", report=report)
    assert store.get("job-2")["state"] == "completed"
    assert store.get("job-2")["report"] == report


def test_update_missing_raises(store: RedisJobStore) -> None:
    with pytest.raises(JobNotFoundError):
        store.update("ghost", state="failed")


def test_entries_expire(store: RedisJobStore) -> None:
    store.create("job-3", "det-0004")
    ttl = store._client.ttl(RedisJobStore.key("job-3"))
    assert 0 < ttl <= JOB_TTL_SECONDS


def test_report_json_roundtrip_matches_api_shape() -> None:
    # _decode_report must tolerate exactly what update() serializes.
    from sentinel_x.api.jobstore import _decode_report

    payload = {"summary": "s", "verification": {"verdict": "grounded"}}
    assert _decode_report(json.dumps(payload)) == payload
    assert _decode_report("") is None
