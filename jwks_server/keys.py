"""RSA key generation, PEM (de)serialization, JWK conversion and DB seeding."""

import base64

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from .db import KeyDatabase, StoredKey

KEY_SIZE = 2048
VALID_LIFETIME_SECONDS = 3600  # an unexpired key is good for one hour
EXPIRED_AGE_SECONDS = 3600  # an expired key expired one hour ago


def generate_private_key() -> rsa.RSAPrivateKey:
    """Generate a fresh RSA key pair."""
    return rsa.generate_private_key(public_exponent=65537, key_size=KEY_SIZE)


def serialize_private_key(private_key: rsa.RSAPrivateKey) -> bytes:
    """PKCS#1 PEM bytes: SQLite has no key type, so keys are stored as text/blob."""
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )


def load_private_key(pem: bytes) -> rsa.RSAPrivateKey:
    """Inverse of serialize_private_key."""
    key = serialization.load_pem_private_key(pem, password=None)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise ValueError("stored key is not an RSA private key")
    return key


def _b64url_uint(value: int) -> str:
    """Big-endian, minimal-length, unpadded base64url encoding of an integer."""
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def to_jwk(stored: StoredKey) -> dict[str, str]:
    """Public half of a stored key as a JWK (RFC 7517 / 7518 section 6.3)."""
    numbers = load_private_key(stored.pem).public_key().public_numbers()
    return {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": str(stored.kid),
        "n": _b64url_uint(numbers.n),
        "e": _b64url_uint(numbers.e),
    }


def create_key(db: KeyDatabase, exp: int) -> StoredKey:
    """Generate a key that expires at `exp`, save it, and return the stored row."""
    pem = serialize_private_key(generate_private_key())
    return StoredKey(kid=db.insert_key(pem, exp), pem=pem, exp=exp)


def ensure_key(db: KeyDatabase, *, expired: bool, now: int) -> StoredKey:
    """Return a valid (or expired) key from the DB, creating one if none exists."""
    found = db.get_key(expired=expired, now=now)
    if found:
        return found
    offset = -EXPIRED_AGE_SECONDS if expired else VALID_LIFETIME_SECONDS
    return create_key(db, now + offset)


def seed_keys(db: KeyDatabase, now: int) -> None:
    """Make sure the DB holds at least one expired key and one unexpired key."""
    ensure_key(db, expired=True, now=now)
    ensure_key(db, expired=False, now=now)
