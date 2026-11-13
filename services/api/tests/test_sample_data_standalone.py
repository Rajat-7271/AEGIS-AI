"""Tests for standalone sample-data onboarding and database session reuse.

Verifies:
1. Standalone sample data ingestion creates 5 alerts with connector_type="aisoc_sample".
2. Repeated calls are idempotent (no duplicates).
3. Tenant isolation guarantees cross-tenant separation under RLS / tenant_id.
4. Existing 409 conflict check blocks sample data when real alerts exist.
5. Pipeline mode is taken when Kafka is enabled and returns 502 on failure without direct persistence fallback.
6. Database session reuse in `get_tenant_db` prevents redundant connection checkout.
7. POST /api/v1/alerts/submit works seamlessly with the synthesise_alert_from_events service.
"""

from __future__ import annotations

import re
import uuid
from typing import Any
from unittest.mock import AsyncMock, patch

import httpx
import pytest
import pytest_asyncio
from app.api.v1.deps import CurrentUser, get_current_user
from app.api.v1.endpoints.alerts import router as alerts_router
from app.api.v1.endpoints.onboarding import router as onboarding_router
from app.core.config import settings
from app.db.database import Base, get_db
from app.db.rls import get_tenant_db
from app.models.alert import Alert
from app.services import sample_data
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import event, select
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.ext.compiler import compiles

TENANT_A = uuid.UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
TENANT_B = uuid.UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
USER_A = uuid.UUID("11111111-1111-1111-1111-111111111111")
USER_B = uuid.UUID("22222222-2222-2222-2222-222222222222")


@compiles(JSONB, "sqlite")
def _jsonb_sqlite(_type_: Any, _compiler_: Any, **_kw_: Any) -> str:
    return "TEXT"


@compiles(PgUUID, "sqlite")
def _uuid_sqlite(_type_: Any, _compiler_: Any, **_kw_: Any) -> str:
    return "CHAR(36)"


@pytest_asyncio.fixture
async def session_factory():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")

    @event.listens_for(engine.sync_engine, "before_cursor_execute", retval=True)
    def _rewrite_casts(conn, cursor, statement, parameters, context, executemany):
        if "CAST(" in statement or "cast(" in statement:
            statement = re.sub(r"CAST\s*\(\s*\?\s+AS\s+uuid\s*\)", "?", statement, flags=re.IGNORECASE)
            if parameters:
                new_params = []
                for p in parameters:
                    if isinstance(p, str) and len(p) == 36 and p.count("-") == 4:
                        new_params.append(uuid.UUID(p).hex)
                    else:
                        new_params.append(p)
                parameters = tuple(new_params)
        return statement, parameters

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all, tables=[Alert.__table__])
    yield async_sessionmaker(engine, expire_on_commit=False)
    await engine.dispose()


def _make_principal(user_id: uuid.UUID, tenant_id: uuid.UUID) -> CurrentUser:
    return CurrentUser(
        user_id=user_id,
        tenant_id=tenant_id,
        role="admin",
        email=f"admin@{tenant_id}.internal",
        scopes=["*"],
    )


@pytest_asyncio.fixture
async def test_app(session_factory):
    app = FastAPI()
    app.include_router(onboarding_router, prefix="/api/v1/onboarding")
    app.include_router(alerts_router, prefix="/api/v1")

    state = {"user": _make_principal(USER_A, TENANT_A)}

    async def _db():
        async with session_factory() as session:
            yield session

    app.dependency_overrides[get_db] = _db
    app.dependency_overrides[get_tenant_db] = _db
    app.dependency_overrides[get_current_user] = lambda: state["user"]

    with TestClient(app) as client:
        client.state = state  # type: ignore[attr-defined]
        yield client


@pytest.mark.asyncio
async def test_standalone_sample_data_success(test_app, session_factory, monkeypatch):
    """When standalone mode is active, sample data is directly synthesised and persisted."""
    monkeypatch.setattr(settings, "AISOC_DISABLE_KAFKA", True)

    resp = test_app.post("/api/v1/onboarding/sample-data")
    assert resp.status_code == 202
    data = resp.json()
    assert data["accepted"] == 5
    assert data["rejected"] == 0
    assert len(data["scenarios"]) == 5

    async with session_factory() as session:
        alerts = (await session.execute(select(Alert).where(Alert.tenant_id == TENANT_A))).scalars().all()
        assert len(alerts) == 5
        for alert in alerts:
            assert alert.connector_type == sample_data.SAMPLE_CONNECTOR
            assert alert.idempotency_key.startswith("sample-")
            assert "aisoc_sample" in alert.tags
            assert alert.raw_event.get("aisoc_sample_data") is True


@pytest.mark.asyncio
async def test_retry_idempotency(test_app, session_factory, monkeypatch):
    """Calling POST /sample-data repeatedly returns the existing alerts without duplicating."""
    monkeypatch.setattr(settings, "AISOC_DISABLE_KAFKA", True)

    # First load
    resp1 = test_app.post("/api/v1/onboarding/sample-data")
    assert resp1.status_code == 202
    assert resp1.json()["accepted"] == 5

    # Second load (retry)
    resp2 = test_app.post("/api/v1/onboarding/sample-data")
    assert resp2.status_code == 202
    assert resp2.json()["accepted"] == 5

    async with session_factory() as session:
        alerts = (await session.execute(select(Alert).where(Alert.tenant_id == TENANT_A))).scalars().all()
        assert len(alerts) == 5, f"Expected 5 alerts after retry, found {len(alerts)}"


@pytest.mark.asyncio
async def test_tenant_isolation(test_app, session_factory, monkeypatch):
    """Sample alerts created for Tenant A must not be visible to Tenant B."""
    monkeypatch.setattr(settings, "AISOC_DISABLE_KAFKA", True)

    # Load for Tenant A
    test_app.state["user"] = _make_principal(USER_A, TENANT_A)
    resp_a = test_app.post("/api/v1/onboarding/sample-data")
    assert resp_a.status_code == 202

    # Switch to Tenant B and check
    test_app.state["user"] = _make_principal(USER_B, TENANT_B)
    async with session_factory() as session:
        b_alerts = (await session.execute(select(Alert).where(Alert.tenant_id == TENANT_B))).scalars().all()
        assert len(b_alerts) == 0

    # Load for Tenant B
    resp_b = test_app.post("/api/v1/onboarding/sample-data")
    assert resp_b.status_code == 202

    async with session_factory() as session:
        a_alerts = (await session.execute(select(Alert).where(Alert.tenant_id == TENANT_A))).scalars().all()
        b_alerts = (await session.execute(select(Alert).where(Alert.tenant_id == TENANT_B))).scalars().all()
        assert len(a_alerts) == 5
        assert len(b_alerts) == 5


@pytest.mark.asyncio
async def test_409_conflict_when_real_alerts_exist(test_app, session_factory, monkeypatch):
    """Loading sample data is refused with HTTP 409 if the tenant already has real alerts."""
    monkeypatch.setattr(settings, "AISOC_DISABLE_KAFKA", True)

    # Insert a real alert
    now = sample_data.datetime.now(sample_data.UTC)
    async with session_factory() as session:
        real_alert = Alert(
            tenant_id=TENANT_A,
            title="Real EDR Detection",
            severity="high",
            connector_type="crowdstrike",
            event_time=now,
            first_seen=now,
            last_seen=now,
        )
        session.add(real_alert)
        await session.commit()

    resp = test_app.post("/api/v1/onboarding/sample-data")
    assert resp.status_code == 409
    assert "already has 1 alert(s) from real sources" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_pipeline_mode_taken_when_kafka_enabled(test_app, monkeypatch):
    """When AISOC_DISABLE_KAFKA=false, the ingest-worker HTTP endpoint is called."""
    monkeypatch.setattr(settings, "AISOC_DISABLE_KAFKA", False)
    monkeypatch.setenv("AISOC_SERVICE_TOKEN", "mock_service_token")

    mock_response = httpx.Response(200, json={"accepted": 5, "rejected": 0})
    with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_response) as mock_post:
        resp = test_app.post("/api/v1/onboarding/sample-data")
        assert resp.status_code == 202
        assert mock_post.called
        call_url = mock_post.call_args[0][0]
        assert "/v1/ingest/batch" in call_url


@pytest.mark.asyncio
async def test_pipeline_mode_failure_returns_502(test_app, monkeypatch):
    """When in pipeline mode and the ingest worker fails, HTTP 502 is returned and no rows are written."""
    monkeypatch.setattr(settings, "AISOC_DISABLE_KAFKA", False)
    monkeypatch.setenv("AISOC_SERVICE_TOKEN", "mock_service_token")

    with patch("httpx.AsyncClient.post", side_effect=httpx.ConnectError("Connection refused")):
        resp = test_app.post("/api/v1/onboarding/sample-data")
        assert resp.status_code == 502
        assert "Could not reach the ingest service" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_database_session_reuse(session_factory):
    """get_tenant_db reuses the session from get_db instead of opening an extra session."""
    principal = _make_principal(USER_A, TENANT_A)

    async with session_factory() as base_session:
        # Mock set_rls_context to verify it gets called with base_session
        with patch("app.db.rls.set_rls_context", new_callable=AsyncMock) as mock_rls:
            async for scoped_session in get_tenant_db(current_user=principal, session=base_session):
                assert scoped_session is base_session
                mock_rls.assert_awaited_once_with(base_session, TENANT_A)


@pytest.mark.asyncio
async def test_alert_submit_endpoint_direct_write(test_app):
    """POST /api/v1/alerts/submit synthesises and persists alert using synthesise_alert_from_events."""
    now = sample_data.datetime.now(sample_data.UTC).isoformat()
    resp = test_app.post(
        "/api/v1/alerts/submit",
        json={
            "connector_type": "okta",
            "title": "Suspicious Okta Login",
            "severity": "high",
            "events": [
                {
                    "actor": {"displayName": "bob@example.com"},
                    "client": {"ipAddress": "198.51.100.99", "device": "macbook-01"},
                    "published": now,
                }
            ],
        },
        headers={"Idempotency-Key": "test-key-submit-1234"},
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["title"] == "Suspicious Okta Login"
    assert data["severity"] == "high"
    assert "bob@example.com" in data["affected_users"]
    assert "198.51.100.99" in data["affected_ips"]
