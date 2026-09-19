"""Tests for key handling, the JWKS endpoint and the /auth endpoint."""

import base64
import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from fastapi.testclient import TestClient

from jwks_server.app import create_app
from jwks_server.keys import KeyStore, _b64url_uint


@pytest.fixture(scope="module")
def store() -> KeyStore:
    return KeyStore()


@pytest.fixture(scope="module")
def client(store: KeyStore) -> TestClient:
    return TestClient(create_app(store))


def _public_key_from_jwk(jwk: dict):
    def to_int(s: str) -> int:
        return int.from_bytes(base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)), "big")

    return RSAPublicNumbers(to_int(jwk["e"]), to_int(jwk["n"])).public_key()


def test_jwks_only_contains_unexpired_key(client, store):
    resp = client.get("/.well-known/jwks.json")
    assert resp.status_code == 200
    kids = [k["kid"] for k in resp.json()["keys"]]
    assert kids == [store.valid.kid]
    assert store.expired.kid not in kids


def test_jwk_fields(client):
    jwk = client.get("/.well-known/jwks.json").json()["keys"][0]
    assert jwk["kty"] == "RSA"
    assert jwk["alg"] == "RS256"
    assert jwk["use"] == "sig"
    assert "=" not in jwk["n"] and "=" not in jwk["e"]


def test_valid_token_verifies_against_jwks(client):
    resp = client.post("/auth")
    assert resp.status_code == 200
    token = resp.text
    kid = jwt.get_unverified_header(token)["kid"]
    jwk = next(k for k in client.get("/.well-known/jwks.json").json()["keys"] if k["kid"] == kid)
    claims = jwt.decode(token, _public_key_from_jwk(jwk), algorithms=["RS256"])
    assert claims["exp"] > time.time()


def test_expired_token_uses_expired_key(client, store):
    resp = client.post("/auth?expired=true")
    assert resp.status_code == 200
    header = jwt.get_unverified_header(resp.text)
    assert header["kid"] == store.expired.kid
    claims = jwt.decode(resp.text, options={"verify_signature": False, "verify_exp": False})
    assert claims["exp"] < time.time()
    with pytest.raises(jwt.ExpiredSignatureError):
        jwt.decode(resp.text, store.expired.private_key.public_key(), algorithms=["RS256"])


def test_expired_param_without_value(client, store):
    resp = client.post("/auth?expired")
    assert jwt.get_unverified_header(resp.text)["kid"] == store.expired.kid


def test_valid_token_kid_is_in_jwks_expired_is_not(client):
    jwks_kids = {k["kid"] for k in client.get("/.well-known/jwks.json").json()["keys"]}
    valid_kid = jwt.get_unverified_header(client.post("/auth").text)["kid"]
    expired_kid = jwt.get_unverified_header(client.post("/auth?expired=1").text)["kid"]
    assert valid_kid in jwks_kids
    assert expired_kid not in jwks_kids


def test_wrong_methods_return_405(client):
    assert client.get("/auth").status_code == 405
    assert client.post("/.well-known/jwks.json").status_code == 405
    assert client.put("/auth").status_code == 405


def test_unknown_path_returns_404(client):
    assert client.get("/nope").status_code == 404


def test_keystore_expiry_over_time(store):
    assert not store.valid.is_expired()
    assert store.expired.is_expired()
    future = time.time() + 7200
    assert store.valid.is_expired(future)
    assert store.jwks(future) == {"keys": []}


def test_kids_are_unique():
    a, b = KeyStore(), KeyStore()
    assert len({a.valid.kid, a.expired.kid, b.valid.kid, b.expired.kid}) == 4


def test_b64url_uint():
    assert _b64url_uint(65537) == "AQAB"
