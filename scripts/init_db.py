"""Convenience script that creates tables directly via SQLAlchemy.

Useful for the test suite or when bootstrapping a brand new SQLite
database without invoking Alembic. Production deployments should use
``alembic upgrade head`` instead.
"""

from __future__ import annotations

import argparse
import logging

from ai_triage.db.models import Base
from ai_triage.db.session import init_engine


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--database-url",
        help="Override the DATABASE_URL from the environment.",
        default=None,
    )
    args = parser.parse_args()

    engine = init_engine(args.database_url)
    Base.metadata.create_all(engine)
    logging.info("Created all tables on %s", engine.url)


if __name__ == "__main__":
    main()
