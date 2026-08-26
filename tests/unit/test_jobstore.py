"""Tests for the in-memory job store and Redis store serialization logic."""

import pytest

from sentinel_x.api.jobstore import InMemoryJobStore, JobNotFoundError


def test_create_and_get() -> None:
    store = InMemoryJobStore()
    store.create("job-1", "det-0001")
    job = store.get("job-1")
    assert job is not None
    assert job["incident_id"] == "det-0001"
    assert job["state"] == "running"
    assert job["report"] is None


def test_get_unknown_returns_none() -> None:
    assert InMemoryJobStore().get("nope") is None


def test_update_fields_and_missing_raises() -> None:
    store = InMemoryJobStore()
    store.create("job-1", "det-0001")
    store.update("job-1", state="completed", report={"summary": "ok"})
    assert store.get("job-1")["state"] == "completed"
    assert store.get("job-1")["report"] == {"summary": "ok"}
    with pytest.raises(JobNotFoundError):
        store.update("missing", state="failed")


def test_eviction_bounded_at_maxsize() -> None:
    import time

    store = InMemoryJobStore(maxsize=2)
    store.create("a", "i")
    time.sleep(0.01)
    store.create("b", "i")
    time.sleep(0.01)
    store.create("c", "i")  # evicts oldest ("a")
    assert store.get("a") is None
    assert store.count() == 2
    assert {j for j in ("b", "c") if store.get(j)} == {"b", "c"}
