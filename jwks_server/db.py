"""SQLite storage for private keys.

Every statement uses `?` placeholders and passes values separately, so nothing
that reaches the database is ever spliced into SQL text (no SQL injection).
"""

import sqlite3
from collections.abc import Iterator
from contextlib import closing, contextmanager
from dataclasses import dataclass
from pathlib import Path

DB_FILENAME = "totally_not_my_privateKeys.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS keys(
    kid INTEGER PRIMARY KEY AUTOINCREMENT,
    key BLOB NOT NULL,
    exp INTEGER NOT NULL
)
"""


# Two fixed statements (no string building); `now` is bound to the `?` at run time.
SELECT_VALID = "SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY exp DESC LIMIT 1"
SELECT_EXPIRED = "SELECT kid, key, exp FROM keys WHERE exp <= ? ORDER BY exp DESC LIMIT 1"


@dataclass(frozen=True)
class StoredKey:
    """One row of the keys table: key ID, PEM-encoded private key, expiry (unix seconds)."""

    kid: int
    pem: bytes
    exp: int


class KeyDatabase:
    """Thin wrapper over the SQLite file that holds the private keys.

    A short-lived connection is opened per call. SQLite connections cannot be
    shared across threads by default, and FastAPI runs sync routes in a thread pool.
    """

    def __init__(self, path: str | Path = DB_FILENAME) -> None:
        """Open (creating if needed) the SQLite file at `path` and ensure the table exists."""
        self.path = str(path)
        with self._connect() as conn:
            conn.execute(SCHEMA)

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        """Open a connection, commit on success, roll back on error, always close."""
        with closing(sqlite3.connect(self.path)) as conn:
            with conn:  # transaction: commit / rollback
                yield conn

    def insert_key(self, pem: bytes, exp: int) -> int:
        """Store a PEM private key that expires at `exp`; returns its new kid."""
        with self._connect() as conn:
            cursor = conn.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (pem, exp))
            return int(cursor.lastrowid)

    def get_key(self, *, expired: bool, now: int) -> StoredKey | None:
        """Newest-expiring key that is expired (exp <= now) or still valid (exp > now)."""
        query = SELECT_EXPIRED if expired else SELECT_VALID
        with self._connect() as conn:
            row = conn.execute(query, (now,)).fetchone()
        return StoredKey(*row) if row else None

    def get_unexpired_keys(self, now: int) -> list[StoredKey]:
        """All keys whose expiry is still in the future, oldest kid first."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY kid", (now,)
            ).fetchall()
        return [StoredKey(*row) for row in rows]
