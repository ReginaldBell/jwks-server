"""Tests for the JWKS endpoint, the /auth endpoint and the server entry point."""

import base64
import sqlite3
from contextlib import closing

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from fastapi.testclient import TestClient

from jwks_server import main as main_module
from jwks_server.app import create_app
from jwks_server.db import DB_FILENAME, KeyDatabase
from jwks_server.keys import to_jwk

from .conftest import count_rows


def _public_key_from_jwk(jwk: dict):
    def to_int(s: str) -> int:
        return int.from_bytes(base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)), "big")

    return RSAPublicNumbers(to_int(jwk["e"]), to_int(jwk["n"])).public_key()


def _jwks_kids(client) -> list[str]:
    return [k["kid"] for k in client.get("/.well-known/jwks.json").json()["keys"]]


def test_startup_seeds_expired_and_valid_keys(db, client, clock):
    now = int(clock())
    assert count_rows(db) == 2
    assert db.get_key(expired=True, now=now).exp <= now
    assert db.get_key(expired=False, now=now).exp >= now + 3600 - 1


def test_jwks_only_contains_unexpired_keys(db, client, clock):
    now = int(clock())
    expired_kid = str(db.get_key(expired=True, now=now).kid)
    valid_kid = str(db.get_key(expired=False, now=now).kid)
    resp = client.get("/.well-known/jwks.json")
    assert resp.status_code == 200
    assert _jwks_kids(client) == [valid_kid]
    assert expired_kid not in _jwks_kids(client)


def test_jwk_fields(client):
    jwk = client.get("/.well-known/jwks.json").json()["keys"][0]
    assert jwk["kty"] == "RSA"
    assert jwk["alg"] == "RS256"
    assert jwk["use"] == "sig"
    assert "=" not in jwk["n"] and "=" not in jwk["e"]


def test_valid_token_verifies_against_jwks(client, clock):
    resp = client.post("/auth")
    assert resp.status_code == 200
    token = resp.text
    kid = jwt.get_unverified_header(token)["kid"]
    jwk = next(k for k in client.get("/.well-known/jwks.json").json()["keys"] if k["kid"] == kid)
    claims = jwt.decode(
        token,
        _public_key_from_jwk(jwk),
        algorithms=["RS256"],
        options={"verify_iat": False, "verify_exp": False},
    )
    assert claims["sub"] == "userABC"
    assert claims["exp"] > clock()


def test_expired_token_uses_expired_key_from_db(db, client, clock):
    now = int(clock())
    expired = db.get_key(expired=True, now=now)
    resp = client.post("/auth?expired=true")
    assert resp.status_code == 200
    assert jwt.get_unverified_header(resp.text)["kid"] == str(expired.kid)
    claims = jwt.decode(resp.text, options={"verify_signature": False, "verify_exp": False})
    assert claims["exp"] < now
    # The expired key signs a token that really does fail expiry validation.
    public_key = _public_key_from_jwk(to_jwk(expired))
    with pytest.raises(jwt.ExpiredSignatureError):
        jwt.decode(resp.text, public_key, algorithms=["RS256"], options={"verify_iat": False})


def test_expired_param_without_value(db, client, clock):
    expired_kid = str(db.get_key(expired=True, now=int(clock())).kid)
    resp = client.post("/auth?expired")
    assert jwt.get_unverified_header(resp.text)["kid"] == expired_kid


def test_valid_token_kid_is_in_jwks_expired_is_not(client):
    jwks_kids = set(_jwks_kids(client))
    valid_kid = jwt.get_unverified_header(client.post("/auth").text)["kid"]
    expired_kid = jwt.get_unverified_header(client.post("/auth?expired=1").text)["kid"]
    assert valid_kid in jwks_kids
    assert expired_kid not in jwks_kids


def test_auth_accepts_basic_auth_and_json_body_like_gradebot(client):
    basic = client.post("/auth", auth=("userABC", "password123"))
    body = client.post("/auth", json={"username": "userABC", "password": "password123"})
    assert basic.status_code == 200 and body.status_code == 200
    assert jwt.decode(body.text, options={"verify_signature": False})["sub"] == "userABC"


def test_repeated_requests_do_not_add_keys(db, client):
    for _ in range(3):
        client.post("/auth")
        client.post("/auth?expired")
        client.get("/.well-known/jwks.json")
    assert count_rows(db) == 2


def test_keys_persist_across_server_restart(tmp_path, clock):
    path = tmp_path / "restart.db"
    first = TestClient(create_app(KeyDatabase(path), clock))
    kids_before = _jwks_kids(first)
    token_kid = jwt.get_unverified_header(first.post("/auth").text)["kid"]

    second = TestClient(create_app(KeyDatabase(path), clock))  # "restart"
    assert _jwks_kids(second) == kids_before
    assert jwt.get_unverified_header(second.post("/auth").text)["kid"] == token_kid
    assert count_rows(KeyDatabase(path)) == 2


def test_new_valid_key_is_created_once_the_old_one_expires(db, client, clock):
    old_kid = _jwks_kids(client)[0]
    clock.now += 2 * 3600  # both seeded keys are now expired
    assert client.get("/.well-known/jwks.json").json() == {"keys": []}

    token = client.post("/auth").text  # signing creates a fresh valid key first
    new_kid = jwt.get_unverified_header(token)["kid"]
    assert new_kid != old_kid
    assert _jwks_kids(client) == [new_kid]
    assert count_rows(db) == 3


def test_private_keys_are_stored_in_the_database_file(db, client):
    with closing(sqlite3.connect(db.path)) as conn:
        pems = [row[0] for row in conn.execute("SELECT key FROM keys")]
    assert len(pems) == 2
    assert all(bytes(p).startswith(b"-----BEGIN RSA PRIVATE KEY-----") for p in pems)


def test_wrong_methods_return_405(client):
    assert client.get("/auth").status_code == 405
    assert client.post("/.well-known/jwks.json").status_code == 405
    assert client.put("/auth").status_code == 405


def test_unknown_path_returns_404(client):
    assert client.get("/nope").status_code == 404


def test_main_creates_db_in_cwd_and_starts_server(tmp_path, monkeypatch):
    calls = {}
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(main_module.uvicorn, "run", lambda app, **kw: calls.update(app=app, **kw))
    main_module.main()
    assert (tmp_path / DB_FILENAME).exists()
    assert calls["port"] == 8080 and calls["host"] == "127.0.0.1"
