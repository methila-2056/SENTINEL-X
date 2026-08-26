"""Initialize the database schema (dev bootstrap).

Usage:
    sentinelx-init-db
"""

from sentinel_x.common.db import create_all
from sentinel_x.common.logging import configure_logging


def main() -> int:
    """Initialize the database schema."""
    configure_logging()
    create_all()
    return 0
