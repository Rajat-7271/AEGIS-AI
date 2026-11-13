"""Restricted, read-only staging entrypoint for the real application API."""

from __future__ import annotations

import base64
import binascii
import os
import re
from collections.abc import Awaitable, Callable, Mapping
from urllib.parse import parse_qs, urlsplit

from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp, Receive, Scope, Send

WORKERS = (
    "OAUTH_REFRESH_WORKER_ENABLED",
    "WEEKLY_DIGEST_WORKER_ENABLED",
    "HUNT_SCHEDULER_ENABLED",
    "RETRO_HUNT_ENABLED",
    "REPORT_SCHEDULER_ENABLED",
    "OUTBOUND_WEBHOOK_WORKER_ENABLED",
    "AISOC_WAR_ROOM_SYNC_ENABLED",
    "RETENTION_WORKER_ENABLED",
    "PHISHING_INTAKE_WORKER_ENABLED",
    "APPROVAL_EXPIRY_ENABLED",
    "SHADOW_RECONCILE_ENABLED",
    "AUTONOMY_DRIFT_ENABLED",
)
SECRETS = (
    "SECRET_KEY",
    "JWT_SECRET",
    "AISOC_CREDENTIAL_KEY",
    "METRICS_TOKEN",
    "REALTIME_INTERNAL_TOKEN",
    "AISOC_REALTIME_JWT_SECRET",
)


def validate_environment(env: Mapping[str, str]) -> None:
    """Fail before importing settings or opening connections; never print values."""
    required = {
        "AISOC_STAGING_ONLY": "1",
        "ENVIRONMENT": "production",
        "AISOC_DEMO_MODE": "false",
        "AISOC_DEV_MODE": "false",
        "AISOC_DEV_AUTH_BYPASS": "0",
        "AISOC_RUN_MIGRATIONS_ON_BOOT": "0",
        **dict.fromkeys(WORKERS, "false"),
        **dict.fromkeys((f"AISOC_DISABLE_{name}" for name in ("KAFKA", "NEO4J", "CLICKHOUSE", "QDRANT")), "true"),
    }
    for key, expected in required.items():
        if env.get(key) != expected:
            raise ValueError(f"Invalid staging setting: {key}")
    if env.get("ENV", "production") != "production":
        raise ValueError("Conflicting staging environment")
    for key in SECRETS:
        value = env.get(key, "")
        if len(value) < 32 or any(c.isspace() for c in value):
            raise ValueError(f"Missing or invalid staging secret: {key}")
    if len({env[key] for key in SECRETS}) != len(SECRETS):
        raise ValueError("Staging secrets must be independent")
    try:
        key_bytes = base64.b64decode(env["AISOC_CREDENTIAL_KEY"], altchars=b"-_", validate=True)
    except (ValueError, binascii.Error):
        raise ValueError("Invalid staging credential encryption key") from None
    if len(key_bytes) != 32:
        raise ValueError("Invalid staging credential encryption key")
    database = urlsplit(env.get("DATABASE_URL", ""))
    if (
        database.scheme != "postgresql+asyncpg"
        or database.hostname != env.get("AISOC_STAGING_DB_HOST")
        or not database.hostname
        or database.username != "aisoc_app"
        or not database.password
        or parse_qs(database.query).get("sslmode") != ["verify-full"]
    ):
        raise ValueError("Invalid isolated staging database configuration")
    if env.get("DATABASE_MIGRATION_URL"):
        raise ValueError("Migration owner credentials forbidden in staging runtime")
    console = urlsplit(env.get("AISOC_CONSOLE_URL", ""))
    if (
        console.scheme != "https"
        or not console.hostname
        or "staging" not in console.hostname.split(".")[0]
        or console.username
        or console.password
        or console.port
        or console.query
        or console.fragment
        or console.path not in {"", "/"}
        or env.get("AISOC_CORS_ORIGINS") != env.get("AISOC_CONSOLE_URL")
    ):
        raise ValueError("Explicit staging console origin and matching CORS origin required")


class ReadOnlyStaging:
    """Deny every capability except login, identity, alert reads and probes."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http":
            path, method = scope["path"], scope["method"]
            permitted = method == "GET" and (
                path
                in {
                    "/livez",
                    "/readyz",
                    "/api/v1/auth/me",
                    "/api/v1/alerts",
                    "/api/v1/alerts/stats",
                    "/api/v1/alerts/queue",
                    "/api/v1/windows-security/status",
                }
                or re.fullmatch(r"/api/v1/alerts/[0-9a-fA-F-]{36}", path) is not None
            )
            permitted |= method == "POST" and path == "/api/v1/auth/login"
            if not permitted:
                from starlette.responses import JSONResponse  # noqa: PLC0415

                await JSONResponse({"detail": "Unavailable in isolated staging"}, status_code=403)(scope, receive, send)
                return
        elif scope["type"] == "websocket":
            await send({"type": "websocket.close", "code": 1008})
            return
        await self.app(scope, receive, send)


def create_app() -> ASGIApp:
    validate_environment(os.environ)
    from sqlalchemy import text  # noqa: PLC0415
    from starlette.responses import JSONResponse  # noqa: PLC0415

    from app.db.database import engine  # noqa: PLC0415
    from app.main import app  # noqa: PLC0415

    @app.middleware("http")
    async def database_readiness(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        if request.url.path == "/readyz":
            try:
                import asyncio  # noqa: PLC0415

                async with asyncio.timeout(3), engine.connect() as connection:
                    await connection.execute(text("SELECT 1 FROM tenants LIMIT 1"))
            except Exception:  # noqa: BLE001 -- response must not disclose connection details
                return JSONResponse({"status": "database unavailable"}, status_code=503)
        return await call_next(request)

    return ReadOnlyStaging(app)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(create_app(), host="0.0.0.0", port=int(os.environ.get("PORT", "8000")), access_log=False)
