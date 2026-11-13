"""Local-only experimental v2 epoch-aware PostgreSQL HTTP receiver.

Not a public service. Do not proxy to the internet or use production DB.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path

from staging_http_adapter import BoundedThreadingHTTPServer, handler_factory
from staging_postgres_epoch_receiver import accept_epoch_batch_postgres
from source_epoch_contract import validate_epoch_batch


def epoch_handler_factory(token, device_id, persist):
    """Reuse the authenticated bounded v1 transport with v2 payload translation.

    The inner handler authenticates and checks the bound device before invoking
    the callback. The callback validates v2 metadata before any DB operation.
    """
    def persist_v2(payload):
        key, events = validate_epoch_batch(payload)
        if key[0] != device_id:
            raise PermissionError("Device identity mismatch")
        return persist(payload)

    return handler_factory(
        Path("unused-v2.sqlite"), token, device_id, persist_batch=persist_v2
    )


def main():
    parser = argparse.ArgumentParser(description="AEGIS AI local v2 PostgreSQL HTTP harness")
    parser.add_argument("--port", type=int, default=8767)
    args = parser.parse_args()
    token = os.environ.get("AEGIS_WINDOWS_STAGING_TOKEN", "")
    device_id = os.environ.get("AEGIS_WINDOWS_DEVICE_ID", "")
    dsn = os.environ.get("AEGIS_WINDOWS_TEST_DATABASE_URL", "")
    if len(token) < 32 or not device_id or len(device_id) > 128 or not all(
        c.isascii() and (c.isalnum() or c in "._-") for c in device_id
    ):
        raise SystemExit("Valid staging token (32+ chars) and device ID required")
    if not dsn:
        raise SystemExit("Set AEGIS_WINDOWS_TEST_DATABASE_URL for isolated test database")
    if not 1 <= args.port <= 65535:
        raise SystemExit("Invalid port")
    try:
        import psycopg
    except ImportError as error:
        raise SystemExit("Install psycopg 3 in the isolated test environment") from error

    def persist(payload):
        with psycopg.connect(dsn, autocommit=True, connect_timeout=5) as connection:
            return accept_epoch_batch_postgres(connection, payload)

    server = BoundedThreadingHTTPServer(
        ("127.0.0.1", args.port), epoch_handler_factory(token, device_id, persist)
    )
    print(f"Local v2 PostgreSQL receiver on 127.0.0.1:{args.port}; no TLS or public exposure")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
