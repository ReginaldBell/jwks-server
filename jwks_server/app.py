"""FastAPI application: JWKS endpoint and mock /auth endpoint."""

import time

import jwt
from fastapi import FastAPI, Query
from fastapi.responses import PlainTextResponse

from .keys import KeyStore

TOKEN_SUBJECT = "userABC"


def create_app(store: KeyStore | None = None) -> FastAPI:
    """Build the app. A store can be injected so tests control the keys."""
    store = store or KeyStore()
    app = FastAPI(title="JWKS Server")

    # Only GET is registered, so FastAPI answers other methods with 405.
    @app.get("/.well-known/jwks.json")
    def jwks() -> dict:
        return store.jwks()

    # Presence of ?expired (even with no value) selects the expired key.
    @app.post("/auth")
    def auth(expired: str | None = Query(default=None)) -> PlainTextResponse:
        record = store.expired if expired is not None else store.valid
        now = int(time.time())
        claims = {"sub": TOKEN_SUBJECT, "iat": now, "exp": record.expires_at}
        token = jwt.encode(
            claims,
            record.private_pem(),
            algorithm="RS256",
            headers={"kid": record.kid},
        )
        return PlainTextResponse(token)

    return app
