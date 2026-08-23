"""Initialize the database schema (dev bootstrap).

Usage:
    python scripts/init_db.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sentinel_x.common.db import create_all  # noqa: E402
from sentinel_x.common.logging import configure_logging  # noqa: E402

if __name__ == "__main__":
    configure_logging()
    create_all()
