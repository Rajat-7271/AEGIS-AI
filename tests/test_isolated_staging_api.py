"""Local staging policy checks; no hosted resources or receipt stores."""

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("staging_serve", ROOT / "services/api/app/scripts/staging_serve.py")
assert spec is not None and spec.loader is not None
staging = importlib.util.module_from_spec(spec)
spec.loader.exec_module(staging)


def environment():
    import base64

    import yaml

    blueprint = yaml.safe_load((ROOT / "infra/render/staging-api.yaml").read_text())
    service = blueprint["services"][0]
    assert service["plan"] == "free"
    assert service["autoDeployTrigger"] == "off"
    assert service["healthCheckPath"] == "/readyz"
    assert service["dockerCommand"] == "python -m app.scripts.staging_serve"
    assert len(blueprint["services"]) == 1
    assert not blueprint.get("databases")
    assert not service.get("domains")
    env = {item["key"]: item.get("value", "") for item in service["envVars"]}
    for index, key in enumerate(staging.SECRETS):
        assert next(item for item in service["envVars"] if item["key"] == key) == {"key": key, "sync": False}
        env[key] = f"synthetic-{index}-" + "a" * 32
    env["AISOC_CREDENTIAL_KEY"] = base64.urlsafe_b64encode(b"synthetic-test-key-material-32!!").decode()
    env["DATABASE_URL"] = "postgresql+asyncpg://aisoc_app:synthetic@isolated.invalid/staging?sslmode=verify-full"
    env["AISOC_STAGING_DB_HOST"] = "isolated.invalid"
    env["AISOC_CONSOLE_URL"] = env["AISOC_CORS_ORIGINS"] = "https://console-staging.invalid"
    return env


def test_blueprint_and_environment():
    staging.validate_environment(environment())


@pytest.mark.parametrize(
    "key",
    [
        *staging.SECRETS,
        *staging.WORKERS,
        "DATABASE_URL",
        "AISOC_STAGING_ONLY",
        "AISOC_STAGING_DB_HOST",
        "AISOC_CONSOLE_URL",
        "AISOC_CORS_ORIGINS",
    ],
)
def test_missing_configuration_fails_without_secret_disclosure(key):
    env = environment()
    env.pop(key)
    with pytest.raises(ValueError) as error:
        staging.validate_environment(env)
    assert "synthetic-" not in str(error.value)
    assert "aisoc_app:" not in str(error.value)


def test_owner_credentials_and_shared_secrets_rejected():
    env = environment()
    env["DATABASE_MIGRATION_URL"] = "secret-owner-dsn"
    with pytest.raises(ValueError, match="owner"):
        staging.validate_environment(env)
    env.pop("DATABASE_MIGRATION_URL")
    env["JWT_SECRET"] = env["SECRET_KEY"]
    with pytest.raises(ValueError, match="independent"):
        staging.validate_environment(env)


@pytest.mark.parametrize(
    "key,value",
    [
        ("ENV", "development"),
        ("AISOC_DEV_AUTH_BYPASS", "1"),
        ("AISOC_CORS_ORIGINS", "*"),
        ("AISOC_CREDENTIAL_KEY", "x" * 44),
        ("DATABASE_URL", "postgresql+asyncpg://postgres:synthetic@isolated.invalid/staging?sslmode=verify-full"),
        ("DATABASE_URL", "postgresql+asyncpg://aisoc_app:synthetic@isolated.invalid/staging?sslmode=disable"),
    ],
)
def test_unsafe_configuration_rejected(key, value):
    env = environment()
    env[key] = value
    with pytest.raises(ValueError):
        staging.validate_environment(env)


def test_websocket_capability_denied():
    from starlette.testclient import TestClient
    from starlette.websockets import WebSocketDisconnect

    async def downstream(scope, receive, send):
        raise AssertionError("WebSockets must never reach the application")

    with pytest.raises(WebSocketDisconnect), TestClient(staging.ReadOnlyStaging(downstream)).websocket_connect("/ws"):
        pass


@pytest.mark.parametrize(
    "method,path,allowed",
    [
        ("GET", "/readyz", True),
        ("GET", "/livez", True),
        ("GET", "/api/v1/alerts", True),
        ("GET", "/api/v1/auth/me", True),
        ("POST", "/api/v1/auth/login", True),
        ("POST", "/v1/ingest/batch", False),
        ("POST", "/api/v1/connectors", False),
        ("POST", "/api/v1/alerts/a/escalate", False),
        ("GET", "/docs", False),
    ],
)
def test_staging_transport_capabilities(method, path, allowed):
    from starlette.testclient import TestClient

    async def downstream(scope, receive, send):
        from starlette.responses import JSONResponse

        await JSONResponse({"forwarded": True})(scope, receive, send)

    response = TestClient(staging.ReadOnlyStaging(downstream)).request(method, path)
    assert response.status_code == (200 if allowed else 403)
    assert "secret" not in json.dumps(response.json())


def test_real_application_refuses_missing_database_and_anonymous_auth():
    """Fresh process prevents cached settings from reaching another environment."""
    import os
    import subprocess
    import sys

    env = {
        key: value
        for key, value in os.environ.items()
        if key.upper()
        in {
            "SYSTEMROOT",
            "SYSTEMDRIVE",
            "WINDIR",
            "PATH",
            "TEMP",
            "TMP",
            "USERPROFILE",
            "LOCALAPPDATA",
            "APPDATA",
            "PROGRAMDATA",
            "HOMEDRIVE",
            "HOMEPATH",
        }
    }
    env.update(environment())
    env["DATABASE_URL"] = "postgresql+asyncpg://aisoc_app:synthetic@127.0.0.1:1/staging?sslmode=verify-full"
    env["AISOC_STAGING_DB_HOST"] = "127.0.0.1"
    env["PYTHONPATH"] = str(ROOT / "services/api")
    code = """
from app.scripts.staging_serve import create_app
from starlette.testclient import TestClient
client = TestClient(create_app())
assert client.get('/livez').status_code == 200
assert client.get('/readyz').status_code == 503
assert client.get('/readyz').json() == {'status': 'database unavailable'}
assert client.get('/api/v1/auth/me').status_code == 401
assert client.post('/v1/ingest/batch', json={}).status_code == 403
"""
    result = subprocess.run([sys.executable, "-c", code], env=env, cwd=ROOT / "services/api", capture_output=True, timeout=90)
    # Do not echo process logs: framework validation errors may include settings.
    assert result.returncode == 0, "Real application readiness/auth check failed; inspect privately"
