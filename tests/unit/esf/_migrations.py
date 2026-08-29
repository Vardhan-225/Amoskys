"""Single source of truth for the migrations the ESF tests need.

Three test files each kept their own list, and adding 017 broke two of them
with column errors that read as "the change broke everything" rather than "a
fixture is behind". A schema list duplicated per file drifts the moment a
migration is added — which is exactly what it did.
"""

import os

ESF_MIGRATIONS = [
    "src/amoskys/storage/migrations/sql/015_esf_exec_forensics.sql",
    "src/amoskys/storage/migrations/sql/016_esf_kernel_events.sql",
    "src/amoskys/storage/migrations/sql/017_esf_quarantine.sql",
]


def apply_esf_schema(conn):
    """Apply every ESF migration, skipping any not present on disk."""
    for path in ESF_MIGRATIONS:
        if not os.path.exists(path):
            continue
        with open(path) as fh:
            conn.executescript(fh.read())
    conn.commit()
