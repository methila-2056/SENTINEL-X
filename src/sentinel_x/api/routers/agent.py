"""Investigation agent endpoints: start async job, poll status/result."""

from __future__ import annotations

import time
import uuid
from contextlib import suppress
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from sentinel_x.api.deps import ROLE_ADMIN, ROLE_ANALYST, require_roles
from sentinel_x.api.jobstore import JobNotFoundError, choose_job_store
from sentinel_x.common.logging import get_logger

logger = get_logger(__name__)
router = APIRouter()

# Chosen once at import: Redis-backed when reachable, bounded in-memory
# otherwise. Survives multi-worker deployments in the Redis case.
_JOBS = choose_job_store()


class InvestigationStart(BaseModel):
    incident_id: str


class InvestigationStatus(BaseModel):
    job_id: str
    incident_id: str
    state: str
    elapsed_s: float | None = None
    report: dict[str, Any] | None = None


@router.post("", response_model=InvestigationStatus)
def start_investigation(
    payload: InvestigationStart,
    analyst: object = Depends(require_roles(ROLE_ANALYST, ROLE_ADMIN)),
) -> InvestigationStatus:
    from sentinel_x.agents.workflows.investigator import InvestigatorAgent

    job_id = f"job-{uuid.uuid4().hex[:8]}"
    _JOBS.create(job_id, payload.incident_id)

    def _run() -> None:
        try:
            report = InvestigatorAgent(max_steps=6).investigate(payload.incident_id)
            _JOBS.update(job_id, state="completed", report=report.to_dict())
        except Exception as exc:  # noqa: BLE001 - job boundary
            logger.error("investigation_job_failed", error=str(exc))
            with suppress(JobNotFoundError):
                _JOBS.update(job_id, state="failed", report={"error": str(exc)})

    import threading

    threading.Thread(target=_run, daemon=True).start()
    return InvestigationStatus(job_id=job_id, incident_id=payload.incident_id, state="running")


@router.get("", response_model=list[InvestigationStatus])
def list_investigations(
    analyst: object = Depends(require_roles(ROLE_ANALYST, ROLE_ADMIN)),
) -> list[InvestigationStatus]:
    """List all investigation jobs (newest first)."""
    jobs = _JOBS.list_jobs()
    return [
        InvestigationStatus(
            job_id=j["job_id"],
            incident_id=j["incident_id"],
            state=j["state"],
            elapsed_s=round(time.time() - j["started"], 1),
            report=j["report"],
        )
        for j in jobs
    ]


@router.get("/{job_id}", response_model=InvestigationStatus)
def get_status(job_id: str) -> InvestigationStatus:
    job = _JOBS.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="job not found")
    return InvestigationStatus(
        job_id=job_id,
        incident_id=job["incident_id"],
        state=job["state"],
        elapsed_s=round(time.time() - job["started"], 1),
        report=job["report"],
    )
