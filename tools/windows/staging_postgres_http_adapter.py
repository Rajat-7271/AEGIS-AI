"""Local-only PostgreSQL HTTP adapter for integration validation.

NOT a staging deployment or public HTTPS service. Binds exclusively to
127.0.0.1 and requires a separately provisioned test PostgreSQL database.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path

from staging_http_adapter import BoundedThreadingHTTPServer, handler_factory
from staging_postgres_receiver import accept_batch_postgres


def main():
    parser = argparse.ArgumentParser(description="AEGIS AI local PostgreSQL receiver harness")
    parser.add_argument("--port", type=int, default=8766)
    args = parser.parse_args()
    token = os.environ.get("AEGIS_WINDOWS_STAGING_TOKEN", "")
    device_id = os.environ.get("AEGIS_WINDOWS_DEVICE_ID", "")
    dsn = os.environ.get("AEGIS_WINDOWS_TEST_DATABASE_URL", "")
    if len(token) < 32 or not device_id or len(device_id) > 128 or not all(
        c.isascii() and (c.isalnum() or c in "._-") for c in device_id
    ):
        raise SystemExit("Valid staging token (32+ chars) and device ID required")
    if not dsn:
        raise SystemExit("Set AEGIS_WINDOWS_TEST_DATABASE_URL for an isolated test database")
    if not 1 <= args.port <= 65535:
        raise SystemExit("Invalid port")
    try:
        import psycopg
    except ImportError as error:
        raise SystemExit("Install psycopg 3 in the isolated test environment") from error

    def persist(payload):
        with psycopg.connect(dsn, autocommit=True, connect_timeout=5) as connection:
            return accept_batch_postgres(connection, payload)

    server = BoundedThreadingHTTPServer(
        ("127.0.0.1", args.port),
        handler_factory(Path("unused.sqlite"), token, device_id, persist_batch=persist),
    )
    print(f"Local PostgreSQL receiver listening on 127.0.0.1:{args.port}; no TLS or public exposure")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
