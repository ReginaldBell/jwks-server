# JWKS Server (Project 1)

A small RESTful JWKS server written in Python (FastAPI + PyJWT + cryptography).

- `GET /.well-known/jwks.json` returns the public keys that have not expired (RS256, with `kid`).
- `POST /auth` returns a signed JWT as the response body (no credentials checked; mocked user).
- `POST /auth?expired` (or `?expired=true`) signs with the expired key and sets an expired `exp`.
- Other methods on these paths return `405`.

Two RSA-2048 keys are generated at startup: one valid for 1 hour and one that expired 1 hour ago.
Each has a unique `kid` (UUID hex) carried in the JWT header.

## Run

    pip install -r requirements.txt
    python -m jwks_server.main        # serves on http://127.0.0.1:8080

## Test, coverage, lint

    python -m pytest                  # prints coverage (currently ~92%)
    python -m ruff check . && python -m ruff format --check .

## Layout

    jwks_server/keys.py   key generation, expiry, JWK conversion, KeyStore
    jwks_server/app.py    FastAPI routes
    jwks_server/main.py   uvicorn entry point (port 8080)
    tests/test_app.py     test suite

## Screenshots to add before submitting

Add screenshots (with your name/identifying info visible) of the grading test client
running against the server and of the `pytest` coverage output.
