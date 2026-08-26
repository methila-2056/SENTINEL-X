"""Seed the database: events -> incidents (ML-scored) -> knowledge graph.

Usage:
    sentinelx-seed [--reset]
"""

import argparse
from pathlib import Path

from sentinel_x.common.logging import configure_logging
from sentinel_x.incidents.pipeline import seed_database

PROJECT_ROOT = Path(__file__).resolve().parents[3]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reset", action="store_true", help="truncate tables first")
    parser.add_argument(
        "--events",
        default=str(PROJECT_ROOT / "data/processed/synthetic/events.parquet"),
        help="canonical events parquet",
    )
    parser.add_argument(
        "--ground-truth",
        default=str(PROJECT_ROOT / "data/processed/synthetic/incidents_ground_truth.json"),
    )
    args = parser.parse_args()
    configure_logging()
    summary = seed_database(
        events_path=Path(args.events),
        ground_truth_path=Path(args.ground_truth),
        reset=args.reset,
    )
    print(summary)
    return 0
