"""Experiment: ingest knowledge sources into PostgreSQL+pgvector.

Usage:
    python experiments/rag/run_ingestion.py [--sigma-limit 3000] [--skip-sigma]
"""

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from sentinel_x.common.logging import configure_logging  # noqa: E402
from sentinel_x.rag.ingestion.pipeline import ingest_all  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sigma-limit", type=int, default=3000)
    parser.add_argument("--skip-mitre", action="store_true")
    parser.add_argument("--skip-sigma", action="store_true")
    parser.add_argument("--skip-playbooks", action="store_true")
    args = parser.parse_args()
    configure_logging()

    stats = ingest_all(
        mitre_path=None if args.skip_mitre else ROOT / "data/raw/mitre/enterprise-attack.json",
        sigma_dir=None if args.skip_sigma else ROOT / "data/raw/sigma/rules",
        playbook_dir=None if args.skip_playbooks else ROOT / "configs/playbooks",
        sigma_limit=args.sigma_limit,
    )
    print("Ingestion complete:", stats)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
