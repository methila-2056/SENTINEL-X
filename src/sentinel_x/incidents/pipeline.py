"""End-to-end ingestion pipeline: events -> ML scores -> incidents -> graph.

Loads canonical events into PostgreSQL, correlates them into incidents,
attaches ML-derived risk, links ground truth where available, and builds
the knowledge graph. Idempotent per event id; safe to re-run.
"""

from __future__ import annotations

import json
import math
from pathlib import Path

import pandas as pd
from sqlalchemy import delete, func, select, update

from sentinel_x.common.db import get_sync_session
from sentinel_x.common.logging import get_logger
from sentinel_x.data.db.models import EdgeRow, EntityRow, IncidentRow, SecurityEventRow
from sentinel_x.graph.entities.extract import extract_entities_and_edges
from sentinel_x.incidents.correlator import correlate_events
from sentinel_x.incidents.risk import score_incident
from sentinel_x.ml.inference.scoring import score_host_minutes

logger = get_logger(__name__)


def _sanitize(df: pd.DataFrame) -> pd.DataFrame:
    """Normalize timestamps and numerics; NaN -> None so DB columns accept values."""
    out = df.copy()
    out["timestamp"] = pd.to_datetime(out["timestamp"], utc=True)
    for col in ("dst_port", "bytes_transferred", "severity"):
        if col in out.columns:
            out[col] = pd.to_numeric(out[col], errors="coerce")
    return out


def _int_or_none(value) -> int | None:
    if value is None or (isinstance(value, float) and math.isnan(value)):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _float_or_none(value) -> float | None:
    if value is None or (isinstance(value, float) and math.isnan(value)):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def load_ground_truth(path: Path) -> dict[str, dict]:
    """Load synthetic ground-truth incidents keyed by their incident id."""
    if not path.exists():
        return {}
    with open(path, encoding="utf-8") as fh:
        rows = json.load(fh)
    return {gt["incident_id"]: gt for gt in rows}


def seed_database(
    events_path: Path,
    ground_truth_path: Path | None = None,
    reset: bool = False,
    min_incident_events: int = 2,
) -> dict:
    """Run the full ingestion pipeline. Returns summary statistics."""
    df = pd.read_parquet(events_path)
    df = _sanitize(df)
    logger.info("pipeline_start", events=len(df))

    with get_sync_session() as session:
        if reset:
            session.execute(delete(EdgeRow))
            session.execute(delete(EntityRow))
            session.execute(delete(IncidentRow))
            session.execute(delete(SecurityEventRow))
            session.commit()
            logger.info("pipeline_reset_tables")

        existing = session.scalar(select(func.count()).select_from(SecurityEventRow)) or 0
        if existing:
            logger.info("events_already_present", count=existing)
            return {"status": "already_seeded", "existing_events": existing}

        # 1. Persist events -------------------------------------------------
        records = []
        for row in df.to_dict("records"):
            meta = row.get("metadata")
            records.append(
                {
                    "id": row["event_id"],
                    "timestamp": row["timestamp"].to_pydatetime(),
                    "source": row.get("source") or "unknown",
                    "event_type": row["event_type"],
                    "action": row.get("action") or "unknown",
                    "user": row.get("user"),
                    "host": row.get("host"),
                    "process": row.get("process"),
                    "src_ip": row.get("src_ip"),
                    "dst_ip": row.get("dst_ip"),
                    "dst_port": _int_or_none(row.get("dst_port")),
                    "file_path": row.get("file_path"),
                    "bytes_transferred": _float_or_none(row.get("bytes_transferred")),
                    "severity": _int_or_none(row.get("severity")) or 0,
                    "label": row.get("label") or "benign",
                    "attack_category": row.get("attack_category"),
                    "technique_id": row.get("technique_id"),
                    "metadata_": meta if isinstance(meta, dict) else {},
                }
            )
        session.bulk_insert_mappings(SecurityEventRow, records)
        session.commit()

        # 2. Correlate + score incidents ------------------------------------
        features = score_host_minutes(df)
        candidates = correlate_events(df)
        ground_truth = load_ground_truth(ground_truth_path) if ground_truth_path else {}

        kept = [c for c in candidates if len(c.member_event_ids) >= min_incident_events]
        incident_records: list[dict] = []
        event_incident_map: dict[str, str] = {}

        for i, cand in enumerate(kept):
            assert cand.first_seen is not None and cand.last_seen is not None, (
                "correlated candidate must have a time span"
            )
            member_mask = df["event_id"].isin(cand.member_event_ids)
            sub = df.loc[member_mask]

            # ML window scores overlapping this incident's host/time span
            ap_values: list[float] = []
            an_values: list[float] = []
            start_m = cand.first_seen.floor("min")
            end_m = cand.last_seen.ceil("min")
            for host in cand.hosts:
                fh = features[features["host"] == host]
                fh = fh[(fh["minute"] >= start_m) & (fh["minute"] <= end_m)]
                ap_values.extend(fh["attack_probability"].tolist())
                an_values.extend(fh["anomaly_score"].tolist())
            attack_probability = max(ap_values) if ap_values else 0.0
            anomaly_score = max(an_values) if an_values else 0.0

            risk = score_incident(
                sub, attack_probability=attack_probability, anomaly_score=anomaly_score
            )

            # Ground-truth link: host overlap + time-range containment
            gt_link = None
            for gt_id, gt in ground_truth.items():
                if not (set(gt.get("compromised_hosts", [])) & cand.hosts):
                    continue
                gt_start = pd.Timestamp(gt["start_time"])
                gt_end = pd.Timestamp(gt["end_time"])
                if cand.first_seen <= gt_end and cand.last_seen >= gt_start:
                    gt_link = gt_id
                    break

            incident_id = f"det-{i:04d}"
            incident_records.append(
                {
                    "id": incident_id,
                    "first_seen": cand.first_seen.to_pydatetime(),
                    "last_seen": cand.last_seen.to_pydatetime(),
                    "status": "open",
                    "severity_label": risk["severity_label"],
                    "risk_score": risk["risk_score"],
                    "anomaly_score": round(anomaly_score, 4),
                    "attack_probability": round(attack_probability, 4),
                    "correlated_event_ids": cand.member_event_ids,
                    "entities": {
                        "users": sorted(cand.users),
                        "hosts": sorted(cand.hosts),
                        "src_ips": sorted(cand.src_ips),
                        "external_ips": sorted(cand.dst_ips_external),
                    },
                    "signals": risk["signals"],
                    "ground_truth_incident_id": gt_link,
                }
            )
            for eid in cand.member_event_ids:
                event_incident_map[eid] = incident_id

        session.bulk_insert_mappings(IncidentRow, incident_records)

        # Stamp events with their incident id in a single batched executemany
        # instead of one round-trip per event.
        if event_incident_map:
            session.execute(
                update(SecurityEventRow),
                [{"id": eid, "incident_id": inc_id} for eid, inc_id in event_incident_map.items()],
            )
        session.commit()

        # 3. Knowledge graph -------------------------------------------------
        n_entities, n_edges = extract_entities_and_edges(records, session)

        true_positives = sum(1 for r in incident_records if r["ground_truth_incident_id"])
        return {
            "status": "seeded",
            "events": len(records),
            "incidents": len(incident_records),
            "gt_linked_incidents": true_positives,
            "graph_entities": n_entities,
            "graph_edges": n_edges,
        }
