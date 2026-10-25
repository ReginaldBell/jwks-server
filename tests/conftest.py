"""Shared fixtures: every test gets its own throwaway SQLite file."""

import sqlite3
import time
from contextlib import closing

import pytest
from fastapi.testclient import TestClient

from jwks_server.app import create_app
from jwks_server.db import KeyDatabase


class FakeClock:
    """Controllable replacement for time.time so tests can move time forward."""

    def __init__(self, start: float | None = None) -> None:
        # Start at the real time so PyJWT (which checks exp against the real clock) agrees.
        self.now = time.time() if start is None else start

    def __call__(self) -> float:
        """Return the current fake time in unix seconds."""
        return self.now


@pytest.fixture
def db(tmp_path) -> KeyDatabase:
    """A fresh, empty key database in a temp directory."""
    return KeyDatabase(tmp_path / "keys.db")


@pytest.fixture
def clock() -> FakeClock:
    """A controllable clock starting at the real current time."""
    return FakeClock()


@pytest.fixture
def client(db: KeyDatabase, clock: FakeClock) -> TestClient:
    """HTTP test client for an app wired to the temp DB and fake clock."""
    return TestClient(create_app(db, clock))


def count_rows(db: KeyDatabase) -> int:
    """Number of rows in the keys table, read through a separate connection."""
    with closing(sqlite3.connect(db.path)) as conn:
        return conn.execute("SELECT COUNT(*) FROM keys").fetchone()[0]
