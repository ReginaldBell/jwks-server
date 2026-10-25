# JWKS Server (Project 2: SQLite-backed keys)

A small RESTful JWKS server written in Python (FastAPI + PyJWT + cryptography + SQLite).
Private keys are stored in a SQLite file so they survive restarts.

- `GET /.well-known/jwks.json` returns the public keys of every unexpired key in the DB (RS256, with `kid`).
- `POST /auth` reads an unexpired private key from the DB, signs a JWT with it and returns the JWT as the response body (no credentials checked; mocked user).
- `POST /auth?expired` (or `?expired=true`) reads an expired key from the DB instead and sets an expired `exp`.
- Other methods on these paths return `405`.

## Database

File: `totally_not_my_privateKeys.db`, created in the current working directory at startup.

    CREATE TABLE IF NOT EXISTS keys(
        kid INTEGER PRIMARY KEY AUTOINCREMENT,
        key BLOB NOT NULL,
        exp INTEGER NOT NULL
    )

- Private keys are saved as PKCS#1 PEM bytes (`key`); `exp` is a unix timestamp; `kid` (the DB row id) is the `kid` in the JWT header and the JWKS.
- At startup the server makes sure the table holds at least one expired key (expired 1 hour ago) and one valid key (valid for 1 hour). Restarting does not add keys that are already there. If time passes and no valid key remains, `POST /auth` creates a new one before signing.
- **SQL injection:** every statement in `jwks_server/db.py` uses `?` placeholders with values passed separately; no SQL is built from strings. `tests/test_db.py` checks that SQL text stored as data is never executed.

## Run

    pip install -r requirements.txt
    python -m jwks_server.main        # serves on http://127.0.0.1:8080

## Test, coverage, lint

    python -m pytest                  # prints coverage (currently ~99%)
    python -m ruff check . && python -m ruff format --check .

## Layout

    jwks_server/db.py     SQLite access: schema and parameterized queries
    jwks_server/keys.py   key generation, PEM (de)serialization, JWK conversion, DB seeding
    jwks_server/app.py    FastAPI routes (/auth and /.well-known/jwks.json)
    jwks_server/main.py   uvicorn entry point (port 8080)
    tests/                test suite (db, keys, app/endpoints)

## Screenshots

- Gradebot (test client) against this server: `screenshots/gradebot.png`
- Test suite with coverage: `screenshots/test_coverage.png`

Run Gradebot with: `gradebot project-2 --dir . --run "python -m jwks_server.main"`
