"""CLI entry point: generate the synthetic scenario dataset.

Usage:
    python scripts/generate_synthetic.py [--days 7] [--attacks 12] [--seed 42]
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sentinel_x.common.logging import configure_logging  # noqa: E402
from sentinel_x.data.ingestion.synthetic import generate_dataset, write_jsonl_sample  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate synthetic security telemetry")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--days", type=int, default=7)
    parser.add_argument("--attacks", type=int, default=12)
    args = parser.parse_args()

    configure_logging()
    out_dir = Path("data/processed/synthetic")
    df, incidents = generate_dataset(
        out_dir, seed=args.seed, days=args.days, n_attacks=args.attacks
    )
    write_jsonl_sample(df, Path("data/samples/synthetic_events_sample.jsonl"))
    print(f"Events: {len(df)} | Incidents: {len(incidents)} | Output: {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
