"""Dedicated staging-only v2 WSGI application behind a trusted HTTPS gateway.

Not wired to the production API. Use a separate staging PostgreSQL database
and a hosting provider that terminates HTTPS before forwarding to WSGI.
"""
from __future__ import annotations

import json
import os
import logging

logger = logging.getLogger(__name__)

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
    method = environ.get("REQUEST_METHOD")
    route = environ.get("PATH_INFO")
    is_readiness = method == "GET" and route == "/v2/health/ready"
    if not is_readiness and (method != "POST" or route != "/v2/windows-security/events"):
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
    if is_readiness:
        try:
            import psycopg
            with psycopg.connect(dsn, connect_timeout=5) as conn:
                with conn.cursor() as cursor:
                    cursor.execute("SELECT to_regclass('windows_pilot.security_events_v2')")
                    ready = cursor.fetchone()[0] is not None
            if not ready:
                logger.warning("staging_readiness_failure category=schema_missing")
                return _reply(start_response, "503 Service Unavailable", {"ready": False})
            return _reply(start_response, "200 OK", {"ready": True})
        except Exception as exc:
            # Never log exception text, DSNs, credentials, hostnames, or SQL.
            category = "database_error"
            sqlstate = getattr(exc, "sqlstate", None)
            if sqlstate == "28P01":
                category = "database_auth_failed"
            elif sqlstate == "42501":
                category = "database_permission_denied"
            elif sqlstate == "3D000":
                category = "database_not_found"
            elif sqlstate == "42P01":
                category = "schema_missing"
            elif sqlstate == "28000":
                category = "database_role_or_pooler_user_invalid"
            elif sqlstate == "53300":
                category = "pooler_capacity"
            elif isinstance(exc, (TimeoutError, ConnectionError)):
                category = "connection_timeout_or_network"
            else:
                name = type(exc).__name__
                if name in ("OperationalError", "InterfaceError"):
                    # libpq often packs connection failures into OperationalError
                    # without SQLSTATE. Classify only known phrases; never log
                    # the message itself, which can include the connection URI.
                    detail = str(exc).lower()
                    if "password authentication failed" in detail or "authentication failed" in detail:
                        category = "database_auth_failed"
                    elif "tenant or user not found" in detail or "invalid user" in detail:
                        category = "pooler_username_or_project_invalid"
                    elif "name or service not known" in detail or "could not translate host name" in detail or "temporary failure in name resolution" in detail:
                        category = "dns_resolution_failed"
                    elif "timeout expired" in detail or "connection timed out" in detail:
                        category = "connection_timeout"
                    elif "connection refused" in detail:
                        category = "connection_refused"
                    elif "network is unreachable" in detail or "no route to host" in detail:
                        category = "network_unreachable"
                    elif "certificate verify failed" in detail or "ssl error" in detail:
                        category = "tls_handshake_failed"
                    elif "database" in detail and "does not exist" in detail:
                        category = "database_not_found"
                    else:
                        category = "database_connection_failed"
            logger.warning("staging_readiness_failure category=%s", category)
            return _reply(start_response, "503 Service Unavailable", {"ready": False})
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
        # Validate the entire v2 envelope before opening a database connection.
        from source_epoch_contract import validate_epoch_batch
        validate_epoch_batch(payload)
        import psycopg
        with psycopg.connect(dsn, autocommit=True, connect_timeout=5) as conn:
            result = accept_epoch_batch_postgres(conn, payload)
    except (InvalidBatch, SourceIdentityError, ValueError, UnicodeError):
        return _reply(start_response, "400 Bad Request", {"error": "invalid_batch"})
    except Exception:
        return _reply(start_response, "503 Service Unavailable", {"error": "storage_unavailable"})
    return _reply(start_response, "200 OK", result)
