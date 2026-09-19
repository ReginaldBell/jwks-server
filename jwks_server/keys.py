"""RSA key generation and an in-memory key store with expiry."""

import base64
import time
import uuid
from dataclasses import dataclass, field

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

KEY_SIZE = 2048
VALID_LIFETIME_SECONDS = 3600  # unexpired key is good for one hour
EXPIRED_AGE_SECONDS = 3600  # expired key expired one hour ago


@dataclass(frozen=True)
class KeyRecord:
    """An RSA private key with its unique key ID (kid) and expiry (unix seconds)."""

    private_key: rsa.RSAPrivateKey
    expires_at: int
    kid: str = field(default_factory=lambda: uuid.uuid4().hex)

    def is_expired(self, now: float | None = None) -> bool:
        return self.expires_at <= (time.time() if now is None else now)

    def private_pem(self) -> bytes:
        """PKCS#8 PEM encoding, the format PyJWT expects for signing."""
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

    def to_jwk(self) -> dict[str, str]:
        """Public half of the key as a JWK (RFC 7517 / 7518 section 6.3)."""
        numbers = self.private_key.public_key().public_numbers()
        return {
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": self.kid,
            "n": _b64url_uint(numbers.n),
            "e": _b64url_uint(numbers.e),
        }


def _b64url_uint(value: int) -> str:
    """Big-endian, minimal-length, unpadded base64url encoding of an integer."""
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def generate_key(expires_at: int) -> KeyRecord:
    """Generate a fresh RSA key pair with a new kid that expires at `expires_at`."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=KEY_SIZE)
    return KeyRecord(private_key=private_key, expires_at=expires_at)


class KeyStore:
    """Holds one currently-valid key and one already-expired key."""

    def __init__(self, now: float | None = None) -> None:
        now = int(time.time() if now is None else now)
        self.valid = generate_key(now + VALID_LIFETIME_SECONDS)
        self.expired = generate_key(now - EXPIRED_AGE_SECONDS)

    def unexpired_keys(self, now: float | None = None) -> list[KeyRecord]:
        return [k for k in (self.valid, self.expired) if not k.is_expired(now)]

    def jwks(self, now: float | None = None) -> dict[str, list[dict[str, str]]]:
        """JWKS document containing only keys that have not expired."""
        return {"keys": [k.to_jwk() for k in self.unexpired_keys(now)]}
