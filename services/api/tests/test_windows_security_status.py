"""HTTP authorization and tenant isolation with real API-key database lookup.

Use only AEGIS_WINDOWS_TEST_DATABASE_URL pointing at a disposable PostgreSQL DB.
The upstream HTTP transport is controlled; authentication/storage are not mocked.
"""

import asyncio
import os
import uuid

import httpx
import pytest
from app.api.v1.deps import get_db
from app.api.v1.endpoints import windows_security
from app.core.security import hash_api_key
from app.db.database import Base
from app.models.tenant import ApiKey, Tenant, User
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool


@pytest.fixture
def client(monkeypatch):
    dsn = os.environ.get("AEGIS_WINDOWS_TEST_DATABASE_URL")
    if not dsn:
        pytest.skip("No disposable PostgreSQL database configured")
    engine = create_async_engine(dsn.replace("postgresql://", "postgresql+asyncpg://", 1), poolclass=NullPool)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    tenants = [uuid.uuid4(), uuid.uuid4()]
    keys = ["aisoc_" + uuid.uuid4().hex for _ in range(3)]

    async def setup():
        async with engine.begin() as connection:
            await connection.run_sync(
                lambda conn: Base.metadata.create_all(conn, tables=[Tenant.__table__, User.__table__, ApiKey.__table__])
            )
        async with sessions() as session:
            session.add_all([Tenant(id=t, name="Windows test", slug="ci-" + t.hex) for t in tenants])
            await session.flush()
            session.add_all(
                [
                    ApiKey(
                        tenant_id=tenants[min(index, 1)],
                        name="Windows test",
                        key_prefix=key[:16],
                        hashed_key=hash_api_key(key),
                        scopes=["connectors:read"] if index < 2 else ["alerts:read"],
                    )
                    for index, key in enumerate(keys)
                ]
            )
            await session.commit()

    asyncio.run(setup())

    async def database():
        async with sessions() as session:
            try:
                yield session
                await session.commit()
            except BaseException:
                await session.rollback()
                raise

    monkeypatch.delenv("AISOC_DEV_AUTH_BYPASS", raising=False)
    monkeypatch.setenv("AEGIS_WINDOWS_STAGING_TENANT_ID", str(tenants[0]))
    monkeypatch.setenv("AEGIS_WINDOWS_STAGING_STATUS_URL", "https://staging.invalid/v2/windows-security/status")
    monkeypatch.setenv("AEGIS_WINDOWS_STAGING_TOKEN", "synthetic-upstream-token-" + "a" * 32)
    app = FastAPI()
    app.include_router(windows_security.router, prefix="/api/v1")
    app.dependency_overrides[get_db] = database
    with TestClient(app) as http:
        yield http, keys
    asyncio.run(engine.dispose())


def test_auth_permission_and_tenant_precede_upstream_access(client, monkeypatch):
    http, keys = client

    def forbidden(*args, **kwargs):
        pytest.fail("Unauthorized or other-tenant request reached staging")

    monkeypatch.setattr(windows_security.httpx, "AsyncClient", forbidden)
    path = "/api/v1/windows-security/status"
    assert http.get(path).status_code == 401
    assert http.get(path, headers={"Authorization": "Bearer aisoc_invalid"}).status_code == 401
    assert http.get(path, headers={"Authorization": f"Bearer {keys[2]}"}).status_code == 403
    # Neither a query parameter nor a forged tenant header changes the key's tenant.
    response = http.get(
        path + "?tenant_id=" + os.environ["AEGIS_WINDOWS_STAGING_TENANT_ID"],
        headers={"Authorization": f"Bearer {keys[1]}", "X-Tenant-Id": os.environ["AEGIS_WINDOWS_STAGING_TENANT_ID"]},
    )
    assert response.status_code == 200
    assert response.json() == {"configured": False}


@pytest.mark.parametrize("token", ["x" * 32 + "\u00e9", "x" * 32 + "\n"])
def test_invalid_configured_token_is_safe_service_error(client, monkeypatch, token):
    http, keys = client
    monkeypatch.setenv("AEGIS_WINDOWS_STAGING_TOKEN", token)

    def forbidden(*args, **kwargs):
        raise AssertionError("Invalid configured token reached upstream client")

    monkeypatch.setattr(windows_security.httpx, "AsyncClient", forbidden)
    response = http.get("/api/v1/windows-security/status", headers={"Authorization": f"Bearer {keys[0]}"})
    assert response.status_code == 503
    assert token not in response.text


@pytest.mark.parametrize(
    "body,status",
    [
        (
            {
                "events_received": 2,
                "last_received_at": "2026-11-13T00:00:00+00:00",
                "highest_record_id": 9,
                "source_epochs": 1,
                "scope": "staging_metadata",
                "detection_pipeline": "not_connected",
            },
            200,
        ),
        ({"configured": True, "events_received": 0}, 503),
        ([], 503),
    ],
)
def test_authorized_status_validates_upstream_contract(client, monkeypatch, body, status):
    http, keys = client
    real_client = httpx.AsyncClient

    def transport(request):
        assert request.headers["Authorization"].startswith("Bearer synthetic-upstream-token-")
        return httpx.Response(200, json=body)

    def upstream(**kwargs):
        assert kwargs["follow_redirects"] is False
        return real_client(**kwargs, transport=httpx.MockTransport(transport))

    monkeypatch.setattr(windows_security.httpx, "AsyncClient", upstream)
    response = http.get("/api/v1/windows-security/status", headers={"Authorization": f"Bearer {keys[0]}"})
    assert response.status_code == status
    if status == 200:
        assert response.json() == {"configured": True, **body}
    else:
        assert "synthetic-upstream-token" not in response.text
