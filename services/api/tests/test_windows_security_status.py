"""HTTP authorization and tenant isolation with real API-key database lookup.

Use only AEGIS_WINDOWS_TEST_DATABASE_URL pointing at a disposable PostgreSQL DB.
DATABASE_MIGRATION_URL creates/seeds its schema; the runtime URL must be a
separate non-owner login without superuser, role-administration or RLS bypass.
The upstream HTTP transport is controlled; authentication/storage are not mocked.
"""

import asyncio
import os
import uuid
from pathlib import Path

import httpx
import pytest
from app.api.v1.deps import get_db
from app.api.v1.endpoints import windows_security
from app.core.security import hash_api_key
from app.db.database import Base
from app.db.rls import set_rls_context
from app.models.tenant import ApiKey, Tenant, User
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool


@pytest.fixture
def client(monkeypatch):
    dsn = os.environ.get("AEGIS_WINDOWS_TEST_DATABASE_URL")
    if not dsn:
        pytest.skip("No disposable PostgreSQL database configured")
    engine = create_async_engine(dsn.replace("postgresql://", "postgresql+asyncpg://", 1), poolclass=NullPool)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    owner_dsn = os.environ["DATABASE_MIGRATION_URL"]
    owner_engine = create_async_engine(owner_dsn.replace("postgresql://", "postgresql+asyncpg://", 1), poolclass=NullPool)
    owner_sessions = async_sessionmaker(owner_engine, expire_on_commit=False)
    tenants = [uuid.uuid4(), uuid.uuid4()]
    keys = ["aisoc_" + uuid.uuid4().hex for _ in range(3)]

    async def setup():
        async with owner_engine.begin() as connection:
            await connection.run_sync(
                lambda conn: Base.metadata.create_all(conn, tables=[Tenant.__table__, User.__table__, ApiKey.__table__])
            )
            # Apply the real migration's helper and API-key policy, rather than
            # letting metadata-only schema creation silently omit RLS.
            migration = (Path(__file__).resolve().parents[1] / "migrations/002_rls.sql").read_text()
            helper = migration.split("CREATE OR REPLACE FUNCTION current_tenant_id()", 1)[1].split("-- cases", 1)[0]
            policy = migration.split("-- api_keys\n", 1)[1].split("-- playbooks", 1)[0]
            raw = await connection.get_raw_connection()
            await raw.driver_connection.execute("CREATE OR REPLACE FUNCTION current_tenant_id()" + helper + policy)
            role = connection.dialect.identifier_preparer.quote(make_url(dsn).username)
            await connection.execute(text(f"GRANT SELECT, UPDATE ON api_keys TO {role}"))
            await connection.execute(text(f"GRANT SELECT ON tenants, users TO {role}"))
        async with owner_sessions() as session:
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
        yield http, keys, tenants, sessions
    asyncio.run(engine.dispose())
    asyncio.run(owner_engine.dispose())


def test_runtime_role_enforces_real_api_key_rls(client):
    _, _, tenants, sessions = client

    async def verify():
        async with sessions() as session:
            role = (
                await session.execute(
                    text("SELECT rolsuper, rolbypassrls, rolcreatedb, rolcreaterole FROM pg_roles WHERE rolname=current_user")
                )
            ).one()
            assert not any(role), "Runtime login must not bypass RLS or administer roles/databases"
            assert not await session.scalar(
                text("SELECT pg_has_role(current_user, relowner, 'MEMBER') FROM pg_class WHERE oid='api_keys'::regclass")
            ), "Runtime login must not own the table or inherit its owner's role"
            assert not await session.scalar(text("SELECT has_schema_privilege(current_user, 'public', 'CREATE')"))
            query = text("SELECT tenant_id FROM api_keys WHERE tenant_id IN (:a, :b)")
            params = {"a": tenants[0], "b": tenants[1]}
            # Authentication needs the migration's unbound-session read arm.
            assert set((await session.execute(query, params)).scalars()) == set(tenants)
            for tenant in tenants:
                await set_rls_context(session, tenant)
                assert set((await session.execute(query, params)).scalars()) == {tenant}
                other = tenants[1] if tenant == tenants[0] else tenants[0]
                result = await session.execute(text("UPDATE api_keys SET name='forbidden' WHERE tenant_id=:other"), {"other": other})
                assert result.rowcount == 0
            # A visible row cannot be moved into another tenant either.
            from sqlalchemy.exc import DBAPIError

            with pytest.raises(DBAPIError, match="row-level security"):
                await session.execute(text("UPDATE api_keys SET tenant_id=:a WHERE tenant_id=:b"), params)
            await session.rollback()

    asyncio.run(verify())


def test_auth_permission_and_tenant_precede_upstream_access(client, monkeypatch):
    http, keys, _, _ = client

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
    http, keys, _, _ = client
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
    http, keys, _, _ = client
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
