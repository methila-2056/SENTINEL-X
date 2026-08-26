"""Seed the database: events -> incidents (ML-scored) -> knowledge graph.

Usage:
    python scripts/seed_pipeline.py [--reset]
"""

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from sentinel_x.common.logging import configure_logging  # noqa: E402
from sentinel_x.incidents.pipeline import seed_database  # noqa: E402

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reset", action="store_true", help="truncate tables first")
    parser.add_argument(
        "--events",
        default=str(ROOT / "data/processed/synthetic/events.parquet"),
        help="canonical events parquet",
    )
    parser.add_argument(
        "--ground-truth",
        default=str(ROOT / "data/processed/synthetic/incidents_ground_truth.json"),
    )
    args = parser.parse_args()

    configure_logging()
    summary = seed_database(
        events_path=Path(args.events),
        ground_truth_path=Path(args.ground_truth),
        reset=args.reset,
    )
    print(summary)
