"""Tests for the SQLite key storage layer."""

import sqlite3
from contextlib import closing

import pytest

from jwks_server.db import DB_FILENAME, KeyDatabase

from .conftest import count_rows

NOW = 1_800_000_000


def test_default_filename_matches_assignment():
    assert DB_FILENAME == "totally_not_my_privateKeys.db"


def test_schema_matches_assignment(db):
    with closing(sqlite3.connect(db.path)) as conn:
        columns = conn.execute("PRAGMA table_info(keys)").fetchall()
    # (cid, name, type, notnull, default, pk)
    assert [(c[1], c[2], c[3], c[5]) for c in columns] == [
        ("kid", "INTEGER", 0, 1),
        ("key", "BLOB", 1, 0),
        ("exp", "INTEGER", 1, 0),
    ]
    with closing(sqlite3.connect(db.path)) as conn:
        sql = conn.execute("SELECT sql FROM sqlite_master WHERE name = 'keys'").fetchone()[0]
    assert "AUTOINCREMENT" in sql


def test_insert_returns_incrementing_kids(db):
    first = db.insert_key(b"one", NOW + 10)
    second = db.insert_key(b"two", NOW + 20)
    assert second == first + 1


def test_get_key_empty_db_returns_none(db):
    assert db.get_key(expired=False, now=NOW) is None
    assert db.get_key(expired=True, now=NOW) is None


def test_get_key_splits_valid_from_expired(db):
    expired_kid = db.insert_key(b"old", NOW - 100)
    valid_kid = db.insert_key(b"new", NOW + 100)
    assert db.get_key(expired=False, now=NOW).kid == valid_kid
    assert db.get_key(expired=True, now=NOW).kid == expired_kid


def test_key_expiring_exactly_now_counts_as_expired(db):
    kid = db.insert_key(b"edge", NOW)
    assert db.get_key(expired=True, now=NOW).kid == kid
    assert db.get_key(expired=False, now=NOW) is None
    assert db.get_unexpired_keys(NOW) == []


def test_get_key_prefers_latest_expiry(db):
    db.insert_key(b"short", NOW + 10)
    longer = db.insert_key(b"long", NOW + 999)
    assert db.get_key(expired=False, now=NOW).kid == longer


def test_get_unexpired_keys_returns_only_valid_rows(db):
    db.insert_key(b"old", NOW - 1)
    a = db.insert_key(b"a", NOW + 5)
    b = db.insert_key(b"b", NOW + 6)
    assert [k.kid for k in db.get_unexpired_keys(NOW)] == [a, b]


def test_blob_round_trips_exactly(db):
    pem = b"-----BEGIN RSA PRIVATE KEY-----\n\x00\xff binary \n-----END RSA PRIVATE KEY-----\n"
    db.insert_key(pem, NOW + 60)
    stored = db.get_key(expired=False, now=NOW)
    assert stored.pem == pem
    assert stored.exp == NOW + 60


def test_sql_payloads_are_stored_as_data_not_executed(db):
    """Values containing SQL must be treated as plain data by the parameterized queries."""
    payload = b"'); DROP TABLE keys; --"
    db.insert_key(payload, NOW + 60)
    db.insert_key(b"second", NOW + 120)
    assert count_rows(db) == 2  # table still exists and holds both rows
    assert db.get_key(expired=False, now=NOW).pem == b"second"
    assert db.get_unexpired_keys(NOW)[0].pem == payload


def test_data_survives_a_new_connection(tmp_path):
    path = tmp_path / "persist.db"
    kid = KeyDatabase(path).insert_key(b"persisted", NOW + 60)
    reopened = KeyDatabase(path)  # simulates a server restart
    assert reopened.get_key(expired=False, now=NOW).kid == kid


def test_failed_transaction_rolls_back(db):
    with pytest.raises(RuntimeError):
        with db._connect() as conn:
            conn.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (b"x", NOW))
            raise RuntimeError("boom")
    assert count_rows(db) == 0
