"""The Agents handoff remains tenant-scoped and fails closed."""

from __future__ import annotations

from types import SimpleNamespace

import httpx
import pytest
from app.workers import response_simulation

pytestmark = pytest.mark.asyncio


async def test_proposal_posts_tenant_context_to_validation_route_and_requires_simulated_false_execution(monkeypatch):
    monkeypatch.setenv("AISOC_AGENTS_SERVICE_TOKEN", "unit-token")
    monkeypatch.setenv("API_SERVICE_URL", "http://api.test")
    captured = {}

    class _Client:
        def __init__(self, **kwargs):
            captured["timeout"] = kwargs["timeout"]

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def post(self, url, *, json, headers):
            captured.update(url=url, payload=json, headers=headers)
            return SimpleNamespace(
                status_code=200,
                json=lambda: {
                    "proposal_status": "proposed",
                    "status": "simulated",
                    "simulated": True,
                    "executed": False,
                    "vendor_id": "crowdstrike",
                },
            )

    monkeypatch.setattr(response_simulation.httpx, "AsyncClient", _Client)
    result = await response_simulation.simulate_proposal(
        alert_id="alert-1",
        run_id="run-1",
        tenant_id="tenant-1",
        capability="isolate_host",
        target="host-1",
        confidence=0.9,
    )
    assert captured["url"] == "http://api.test/api/v1/playbook-steps/alert-response-simulation"
    assert captured["payload"]["tenant_id"] == "tenant-1"
    assert captured["headers"] == {"X-AiSOC-Service-Token": "unit-token"}
    assert result["status"] == "simulated"
    assert result["simulated"] is True
    assert result["executed"] is False


async def test_missing_service_token_does_not_make_a_request(monkeypatch):
    monkeypatch.delenv("AISOC_AGENTS_SERVICE_TOKEN", raising=False)

    class _NoRequest:
        def __init__(self, **_kwargs):
            raise AssertionError("request attempted without service authentication")

    monkeypatch.setattr(response_simulation.httpx, "AsyncClient", _NoRequest)
    result = await response_simulation.simulate_proposal(
        alert_id="alert-1",
        run_id="run-1",
        tenant_id="tenant-1",
        capability="isolate_host",
        target="host-1",
        confidence=0.9,
    )
    assert result["status"] == "failed"
    assert result["simulated"] is False
    assert result["executed"] is False


async def test_timeout_or_transport_error_is_not_reported_as_simulated(monkeypatch):
    monkeypatch.setenv("AISOC_AGENTS_SERVICE_TOKEN", "unit-token")

    class _Client:
        def __init__(self, **_kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def post(self, *_args, **_kwargs):
            raise httpx.ReadTimeout("timeout")

    monkeypatch.setattr(response_simulation.httpx, "AsyncClient", _Client)
    result = await response_simulation.simulate_proposal(
        alert_id="alert-1",
        run_id="run-1",
        tenant_id="tenant-1",
        capability="isolate_host",
        target="host-1",
        confidence=0.9,
    )
    assert result["status"] == "failed"
    assert result["simulated"] is False
    assert result["executed"] is False


async def test_contradictory_execution_claim_is_failed_and_visible(monkeypatch):
    monkeypatch.setenv("AISOC_AGENTS_SERVICE_TOKEN", "unit-token")

    class _Client:
        def __init__(self, **_kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def post(self, *_args, **_kwargs):
            return SimpleNamespace(
                status_code=200,
                json=lambda: {"status": "simulated", "simulated": True, "executed": True},
            )

    monkeypatch.setattr(response_simulation.httpx, "AsyncClient", _Client)
    result = await response_simulation.simulate_proposal(
        alert_id="alert-1",
        run_id="run-1",
        tenant_id="tenant-1",
        capability="isolate_host",
        target="host-1",
        confidence=0.9,
    )
    assert result["status"] == "failed"
    assert result["simulated"] is False
    assert result["executed"] is True
