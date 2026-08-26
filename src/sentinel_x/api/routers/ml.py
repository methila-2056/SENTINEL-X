"""Batch scoring endpoint: score raw events via ML without full ingestion.

POST /api/ml/score takes a list of event dicts and returns per-event
attack_probability and anomaly_score. Useful for ad-hoc analysis,
historical re-scoring, and external tool integration.
"""

from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel, Field

from sentinel_x.ml.inference.scoring import score_host_minutes

router = APIRouter()


class ScoreEvent(BaseModel):
    event_id: str
    host: str | None = None
    user: str | None = None
    event_type: str | None = None
    action: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    bytes_transferred: int | None = None


class ScoredEvent(BaseModel):
    event_id: str
    attack_probability: float | None = None
    anomaly_score: float | None = None


class ScoreRequest(BaseModel):
    events: list[ScoreEvent] = Field(..., min_length=1, max_length=500)


class ScoreResponse(BaseModel):
    scored: list[ScoredEvent]
    n_events: int


@router.post("/score", response_model=ScoreResponse)
def score_events(req: ScoreRequest) -> ScoreResponse:
    """Score a batch of events using loaded ML models.

    Events are converted to a DataFrame, scored via the host-minute feature
    pipeline, and returned with per-event attack probability and anomaly score.
    """
    import pandas as pd

    records = [e.model_dump() for e in req.events]
    df = pd.DataFrame(records)
    if "timestamp" not in df.columns:
        import datetime

        df["timestamp"] = pd.Timestamp(datetime.datetime.now(datetime.UTC))

    scored_df = score_host_minutes(df)

    scored: list[ScoredEvent] = []
    if scored_df.empty:
        for ev in req.events:
            scored.append(ScoredEvent(event_id=ev.event_id))
    else:
        id_to_scores: dict[str, dict[str, float | None]] = {}
        for _, row in scored_df.iterrows():
            eid = str(row.get("event_id", ""))
            if eid not in id_to_scores:
                id_to_scores[eid] = {
                    "attack_probability": float(row["attack_probability"]),
                    "anomaly_score": float(row["anomaly_score"]),
                }
        for ev in req.events:
            scores = id_to_scores.get(ev.event_id, {})
            scored.append(
                ScoredEvent(
                    event_id=ev.event_id,
                    attack_probability=scores.get("attack_probability"),
                    anomaly_score=scores.get("anomaly_score"),
                )
            )

    return ScoreResponse(scored=scored, n_events=len(req.events))
