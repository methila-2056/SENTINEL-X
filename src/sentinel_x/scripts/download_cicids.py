"""Download CIC-IDS2017 raw CSVs into data/raw/cicids2017/.

Usage:
    sentinelx-download-cicids [--only FILE ...]
"""

import argparse
import asyncio
from pathlib import Path

from sentinel_x.common.logging import configure_logging
from sentinel_x.data.ingestion.download import FILES, download_dataset


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
