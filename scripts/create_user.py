"""Create or update an API user account.

Usage:
    python scripts/create_user.py --username admin --password 'S3cret!' --role admin
"""

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from sentinel_x.api.deps import KNOWN_ROLES  # noqa: E402
from sentinel_x.api.security import hash_password  # noqa: E402
from sentinel_x.common.db import get_sync_session  # noqa: E402
from sentinel_x.common.logging import configure_logging, get_logger  # noqa: E402
from sentinel_x.data.db.models import UserRow  # noqa: E402

logger = get_logger(__name__)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--username", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--role", default="viewer", choices=sorted(KNOWN_ROLES))
    args = parser.parse_args()

    configure_logging()
    with get_sync_session() as session:
        existing = session.query(UserRow).filter_by(username=args.username).first()
        if existing is None:
            session.add(
                UserRow(
                    username=args.username,
                    password_hash=hash_password(args.password),
                    role=args.role,
                )
            )
            action = "created"
        else:
            # Password/role rotation for an existing account.
            existing.password_hash = hash_password(args.password)
            existing.role = args.role
            action = "updated"
        session.commit()
    logger.info("user_saved", username=args.username, role=args.role, action=action)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
