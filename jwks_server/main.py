"""Entry point: `python -m jwks_server.main` serves on port 8080.

The key database is created in the current working directory, where the
Gradebot client looks for it.
"""

import uvicorn

from .app import create_app


def main() -> None:
    """Create the app (and the key database) and serve it on 127.0.0.1:8080."""
    uvicorn.run(create_app(), host="127.0.0.1", port=8080)


if __name__ == "__main__":
    main()
