"""Dedicated staging-only v2 WSGI application behind a trusted HTTPS gateway.

Not wired to the production API. Use a separate staging PostgreSQL database
and a hosting provider that terminates HTTPS before forwarding to WSGI.
"""
from __future__ import annotations

import json
import os

from source_epoch_contract import SourceIdentityError
from staging_receiver import MAX_REQUEST_BYTES, InvalidBatch, authorize
from staging_postgres_epoch_receiver import accept_epoch_batch_postgres


def _reply(start_response, status, payload):
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    start_response(status, [
        ("Content-Type", "application/json"),
        ("Content-Length", str(len(body))),
        ("Cache-Control", "no-store"),
    ])
    return [body]


def application(environ, start_response):
    """Fail closed: authentication precedes any database access."""
    if environ.get("REQUEST_METHOD") != "POST" or environ.get("PATH_INFO") != "/v2/windows-security/events":
        return _reply(start_response, "404 Not Found", {"error": "not_found"})
    token = os.environ.get("AEGIS_WINDOWS_STAGING_TOKEN", "")
    device = os.environ.get("AEGIS_WINDOWS_DEVICE_ID", "")
    dsn = os.environ.get("AEGIS_WINDOWS_STAGING_DATABASE_URL", "")
    if len(token) < 32 or not device or not dsn:
        return _reply(start_response, "503 Service Unavailable", {"error": "not_configured"})
    auth = environ.get("HTTP_AUTHORIZATION", "")
    try:
        if not auth.startswith("Bearer "):
            raise PermissionError("Missing bearer")
        authorize(auth[7:], token)
    except PermissionError:
        return _reply(start_response, "401 Unauthorized", {"error": "unauthorized"})
    if environ.get("CONTENT_TYPE", "").split(";")[0].strip().lower() != "application/json":
        return _reply(start_response, "415 Unsupported Media Type", {"error": "content_type"})
    raw_length = environ.get("CONTENT_LENGTH", "")
    if not raw_length.isdecimal():
        return _reply(start_response, "411 Length Required", {"error": "content_length"})
    length = int(raw_length)
    if length < 1 or length > MAX_REQUEST_BYTES:
        return _reply(start_response, "413 Payload Too Large", {"error": "payload_size"})
    try:
        raw = environ["wsgi.input"].read(length)
        if len(raw) != length:
            raise InvalidBatch("Truncated request")
        payload = json.loads(raw)
        if not isinstance(payload, dict) or payload.get("device_id") != device:
            return _reply(start_response, "403 Forbidden", {"error": "device_mismatch"})
        import psycopg
        with psycopg.connect(dsn, autocommit=True, connect_timeout=5) as conn:
            result = accept_epoch_batch_postgres(conn, payload)
    except (InvalidBatch, SourceIdentityError, ValueError, UnicodeError):
        return _reply(start_response, "400 Bad Request", {"error": "invalid_batch"})
    except Exception:
        return _reply(start_response, "503 Service Unavailable", {"error": "storage_unavailable"})
    return _reply(start_response, "200 OK", result)
