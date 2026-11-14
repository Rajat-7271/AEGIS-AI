"""Real launcher, orchestrator and PostgreSQL; deliberately no model gateway.

No telemetry or provider responses are invented. An unavailable model must
produce a persisted failed investigation and the poll response must agree.
"""

from __future__ import annotations

import os
import uuid

import asyncpg
import httpx
import pytest
from app.api import investigate
from fastapi import FastAPI


@pytest.mark.integration
@pytest.mark.asyncio
async def test_real_startup_persists_model_failure(monkeypatch):
    dsn = os.environ.get("DATABASE_URL", "")
    if not dsn:
        pytest.skip("requires a disposable migrated PostgreSQL database")
    tenant = uuid.uuid4()
    case_id = str(uuid.uuid4())
    token = "integration-test-only-service-token"
    monkeypatch.setenv("AISOC_AGENTS_SERVICE_TOKEN", token)
    monkeypatch.setenv("AISOC_INVESTIGATE_USE_ROUTER", "0")
    monkeypatch.setenv("LLM_GATEWAY_URL", "")
    monkeypatch.setenv("OPENAI_BASE_URL", "")
    monkeypatch.setenv("LLM_BASE_URL", "")
    monkeypatch.setenv("AISOC_MODEL_PIN_RECON", "aisoc-recon")
    monkeypatch.setenv("AISOC_API_URL", "http://127.0.0.1:1")
    monkeypatch.setenv("AISOC_UEBA_URL", "http://127.0.0.1:1")
    monkeypatch.setattr(investigate, "_REALTIME_URL", "http://127.0.0.1:1")
    await investigate.ledger.close_pool()
    conn = await asyncpg.connect(investigate.ledger._normalise_dsn(dsn))
    run_id = None
    try:
        await conn.execute("INSERT INTO tenants (id, name, slug) VALUES ($1, 'Startup test', $2)", tenant, str(tenant))
        app = FastAPI()
        app.include_router(investigate.router)
        headers = {"Authorization": f"Bearer {token}", "X-AiSOC-Tenant-ID": str(tenant)}
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test", headers=headers) as client:
            response = await client.post(
                f"/api/v1/cases/{case_id}/investigate",
                json={"tenant_id": str(tenant), "alert_summary": "Test case with no telemetry; no evidence supplied.", "raw_alert": {}},
            )
            assert response.status_code == 200, response.text
            run_id = response.json()["run_id"]
            row = await conn.fetchrow(
                "SELECT status, error, raw_alert FROM investigation_runs WHERE id=$1 AND tenant_id=$2", uuid.UUID(run_id), tenant
            )
            assert row is not None, "accepted startup did not create a real ledger row"
            assert row["status"] == "failed"
            assert "gateway" in row["error"].lower()
            result = await client.get(f"/api/v1/investigations/{run_id}")
            assert result.json()["status"] == row["status"]
            assert result.json()["error"] == row["error"]
            report = await client.get(f"/api/v1/investigations/{run_id}/report.md")
            assert report.status_code == 409
            assert not result.json().get("forensic")
    finally:
        if run_id:
            investigate._runs.pop(run_id, None)
        await investigate.ledger.close_pool()
        # The ledger is append-only. Keep this unique test tenant and its run
        # in the disposable integration database rather than bypassing guards.
        await conn.close()
