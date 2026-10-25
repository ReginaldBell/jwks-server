"""Tests for key serialization, JWK conversion and DB seeding."""

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from jwks_server.keys import (
    _b64url_uint,
    create_key,
    ensure_key,
    generate_private_key,
    load_private_key,
    seed_keys,
    serialize_private_key,
    to_jwk,
)

from .conftest import count_rows

NOW = 1_800_000_000


def test_b64url_uint():
    assert _b64url_uint(65537) == "AQAB"


def test_pem_round_trip_is_pkcs1():
    key = generate_private_key()
    pem = serialize_private_key(key)
    assert pem.startswith(b"-----BEGIN RSA PRIVATE KEY-----")  # PKCS#1
    assert load_private_key(pem).private_numbers() == key.private_numbers()


def test_load_private_key_rejects_non_rsa_keys():
    pem = ed25519.Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    with pytest.raises(ValueError):
        load_private_key(pem)


def test_to_jwk_uses_db_kid_and_public_fields(db):
    stored = create_key(db, NOW + 60)
    jwk = to_jwk(stored)
    assert jwk["kid"] == str(stored.kid)
    assert (jwk["kty"], jwk["alg"], jwk["use"], jwk["e"]) == ("RSA", "RS256", "sig", "AQAB")
    assert "d" not in jwk  # never leak private material


def test_seed_creates_one_expired_and_one_valid_key(db):
    seed_keys(db, NOW)
    assert count_rows(db) == 2
    assert db.get_key(expired=True, now=NOW).exp < NOW
    assert db.get_key(expired=False, now=NOW).exp > NOW


def test_seed_is_idempotent(db):
    seed_keys(db, NOW)
    seed_keys(db, NOW)
    assert count_rows(db) == 2


def test_ensure_key_reuses_existing_key(db):
    first = ensure_key(db, expired=False, now=NOW)
    assert ensure_key(db, expired=False, now=NOW).kid == first.kid
    assert count_rows(db) == 1
