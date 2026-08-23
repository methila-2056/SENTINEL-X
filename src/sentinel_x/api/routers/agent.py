"""Investigation agent endpoints: start async job, poll status/result."""

from __future__ import annotations

import time
import uuid
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from sentinel_x.common.logging import get_logger

logger = get_logger(__name__)
router = APIRouter()

_JOBS: dict[str, dict[str, Any]] = {}


class InvestigationStart(BaseModel):
    incident_id: str


class InvestigationStatus(BaseModel):
    job_id: str
    incident_id: str
    state: str
    elapsed_s: float | None = None
    report: dict[str, Any] | None = None


@router.post("", response_model=InvestigationStatus)
def start_investigation(payload: InvestigationStart) -> InvestigationStatus:
    from sentinel_x.agents.workflows.investigator import InvestigatorAgent

    job_id = f"job-{uuid.uuid4().hex[:8]}"
    _JOBS[job_id] = {
        "incident_id": payload.incident_id,
        "state": "running",
        "started": time.time(),
        "report": None,
    }

    def _run() -> None:
        try:
            report = InvestigatorAgent(max_steps=6).investigate(payload.incident_id)
            _JOBS[job_id]["report"] = report.to_dict()
            _JOBS[job_id]["state"] = "completed"
        except Exception as exc:  # noqa: BLE001 - job boundary
            logger.error("investigation_job_failed", error=str(exc))
            _JOBS[job_id]["state"] = "failed"
            _JOBS[job_id]["report"] = {"error": str(exc)}

    import threading

    threading.Thread(target=_run, daemon=True).start()
    return InvestigationStatus(job_id=job_id, incident_id=payload.incident_id, state="running")


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
