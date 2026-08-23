"""CLI entry point: download CIC-IDS2017 raw CSVs into data/raw/cicids2017/.

Usage:
    python scripts/download_cicids2017.py [--only FILE ...]
"""

import argparse
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sentinel_x.common.logging import configure_logging  # noqa: E402
from sentinel_x.data.ingestion.download import FILES, download_dataset  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Download CIC-IDS2017 CSVs")
    parser.add_argument("--only", nargs="*", default=None, help="Subset of filenames")
    args = parser.parse_args()

    if args.only:
        unknown = set(args.only) - set(FILES)
        if unknown:
            parser.error(f"Unknown files: {unknown}")

    configure_logging()
    raw_dir = Path("data/raw/cicids2017")
    downloaded = asyncio.run(download_dataset(raw_dir, only=args.only))
    print(f"Downloaded {len(downloaded)}/{len(FILES or args.only)} files -> {raw_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
