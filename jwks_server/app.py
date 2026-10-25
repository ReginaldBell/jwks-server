"""FastAPI application: JWKS endpoint and mock /auth endpoint, backed by SQLite."""

import time
from collections.abc import Callable

import jwt
from fastapi import FastAPI, Query
from fastapi.responses import PlainTextResponse

from .db import KeyDatabase
from .keys import ensure_key, seed_keys, to_jwk

TOKEN_SUBJECT = "userABC"


def create_app(
    db: KeyDatabase | None = None,
    clock: Callable[[], float] = time.time,
) -> FastAPI:
    """Build the app. The DB and clock can be injected so tests control keys and time."""
    db = db or KeyDatabase()
    seed_keys(db, int(clock()))  # guarantee one expired and one valid key at startup
    app = FastAPI(title="JWKS Server")

    # Only GET is registered, so FastAPI answers other methods with 405.
    @app.get("/.well-known/jwks.json")
    def jwks() -> dict:
        """Public JWKs for every key in the DB that has not expired."""
        keys = db.get_unexpired_keys(int(clock()))
        return {"keys": [to_jwk(k) for k in keys]}

    # Presence of ?expired (even with no value) selects the expired key.
    @app.post("/auth")
    def auth(expired: str | None = Query(default=None)) -> PlainTextResponse:
        """Mock login: sign a JWT with a valid key, or an expired key if ?expired is present."""
        now = int(clock())
        record = ensure_key(db, expired=expired is not None, now=now)
        claims = {"sub": TOKEN_SUBJECT, "iat": now, "exp": record.exp}
        token = jwt.encode(
            claims,
            record.pem,
            algorithm="RS256",
            headers={"kid": str(record.kid)},
        )
        return PlainTextResponse(token)

    return app
