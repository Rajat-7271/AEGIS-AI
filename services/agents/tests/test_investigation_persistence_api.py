
from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
from app.api import investigate as investigate_mod
from app.api import router as agent_runs_mod
from app.security.tenant_scope import TenantPrincipal, require_console_or_service_auth
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

TENANT_A = uuid.UUID("aaaaaaaa-0000-0000-0000-00000000000a")
TENANT_B = uuid.UUID("bbbbbbbb-0000-0000-0000-00000000000b")
RUN_ID = str(uuid.UUID("78191af6-6f87-4256-8288-31b583c71635"))


@pytest.fixture
def setup_api(monkeypatch: pytest.MonkeyPatch) -> tuple[TestClient, dict[str, Any]]:
    state: dict[str, Any] = {
        "runs": {},
        "artifacts": {},
        "tenant_id": TENANT_A,
        "rls_tenants": [],
        "active_tenant": None,
    }

    class Transaction:
        async def __aenter__(self) -> None:
            return None

        async def __aexit__(self, *_: Any) -> None:
            return None

    class Connection:
        def transaction(self) -> Transaction:
            return Transaction()

        async def execute(self, query: str, tenant_id: str) -> None:
            assert "set_config('app.current_tenant_id'" in query
            state["active_tenant"] = uuid.UUID(tenant_id)
            state["rls_tenants"].append(state["active_tenant"])

        async def fetchrow(self, query: str, run_id: uuid.UUID, tenant_id: uuid.UUID):
            assert "WHERE id = $1 AND tenant_id = $2" in query
            assert state["active_tenant"] == tenant_id
            return state["runs"].get((run_id, tenant_id))

        async def fetch(self, query: str, run_id: uuid.UUID, tenant_id: uuid.UUID):
            assert "WHERE run_id = $1" in query
            assert "AND tenant_id = $2" in query
            assert state["active_tenant"] == tenant_id
            return state["artifacts"].get((run_id, tenant_id), [])

    class Pool:
        async def __aenter__(self) -> Connection:
            return Connection()

        async def __aexit__(self, *_: Any) -> None:
            return None

        def acquire(self) -> Pool:
            return self

    pool = Pool()

    async def get_pool() -> Pool:
        return pool

    app = FastAPI()
    app.include_router(investigate_mod.router)
    app.dependency_overrides[require_console_or_service_auth] = lambda: TenantPrincipal(
        tenant_ids=frozenset({state["tenant_id"]}), subject="persistence-test"
    )

    monkeypatch.setattr(investigate_mod.ledger, "get_pool", get_pool)
    monkeypatch.setattr(investigate_mod, "_runs", {}, raising=True)
    return TestClient(app), state


def test_completed_run_is_retrieved_after_memory_state_is_lost(setup_api) -> None:
    client, state = setup_api
    state["runs"][(uuid.UUID(RUN_ID), TENANT_A)] = {
        "run_id": RUN_ID,
        "id": uuid.UUID(RUN_ID),
        "tenant_id": TENANT_A,
        "case_id": "case-123",
        "status": "completed",
        "alert_summary": "Suspicious login",
        "raw_alert": {},
        "model_used": "local",
        "error": None,
        "total_tokens": 12,
        "total_cost_usd": 0.01,
        "iterations": 4,
        "started_at": datetime(2026, 1, 1, tzinfo=UTC),
        "completed_at": datetime(2026, 1, 1, 0, 1, tzinfo=UTC),
    }
    state["artifacts"][(uuid.UUID(RUN_ID), TENANT_A)] = [
        {"kind": "report_md", "content": "Incident report"},
        {"kind": "report_html", "content": "<html>Incident report</html>"},
    ]

    response = client.get(f"/api/v1/investigations/{RUN_ID}")

    assert response.status_code == 200
    assert response.json()["run_id"] == RUN_ID
    assert response.json()["status"] == "completed"
    assert "report_md" not in response.json()
    assert state["rls_tenants"] == [TENANT_A]

    markdown = client.get(f"/api/v1/investigations/{RUN_ID}/report.md")
    html = client.get(f"/api/v1/investigations/{RUN_ID}/report.html")
    assert markdown.status_code == 200
    assert markdown.text == "Incident report"
    assert html.status_code == 200
    assert html.text == "<html>Incident report</html>"


def test_missing_persisted_run_returns_404(setup_api) -> None:
    client, _ = setup_api

    response = client.get(f"/api/v1/investigations/{RUN_ID}")

    assert response.status_code == 404


def test_run_outside_tenant_scope_returns_404(setup_api) -> None:
    client, state = setup_api
    state["runs"][(uuid.UUID(RUN_ID), TENANT_A)] = {
        "id": uuid.UUID(RUN_ID),
        "tenant_id": TENANT_A,
        "run_id": RUN_ID,
        "case_id": "case-123",
        "status": "completed",
    }
    state["tenant_id"] = TENANT_B

    response = client.get(f"/api/v1/investigations/{RUN_ID}")

    assert response.status_code == 404


def test_in_memory_run_from_another_tenant_returns_404(setup_api) -> None:
    client, state = setup_api
    state["tenant_id"] = TENANT_B
    investigate_mod._runs[RUN_ID] = {
        "run_id": RUN_ID,
        "case_id": "case-123",
        "tenant_id": str(TENANT_A),
        "status": "completed",
        "report_md": "Private report",
    }

    response = client.get(f"/api/v1/investigations/{RUN_ID}")
    assert response.status_code == 404


def test_in_memory_run_hides_its_internal_tenant_id(setup_api) -> None:
    client, _ = setup_api
    investigate_mod._runs[RUN_ID] = {
        "run_id": RUN_ID,
        "case_id": "case-123",
        "tenant_id": str(TENANT_A),
        "status": "completed",
    }

    response = client.get(f"/api/v1/investigations/{RUN_ID}")
    assert response.status_code == 200
    assert "tenant_id" not in response.json()


def test_websocket_refuses_another_tenants_in_memory_run(
    setup_api, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, _ = setup_api
    investigate_mod._runs[RUN_ID] = {
        "run_id": RUN_ID,
        "tenant_id": str(TENANT_A),
        "status": "completed",
        "audit_log": [],
    }

    async def principal_for_tenant_b(_ws) -> TenantPrincipal:
        return TenantPrincipal(tenant_ids=frozenset({TENANT_B}), subject="test")

    monkeypatch.setattr(investigate_mod, "_ws_principal", principal_for_tenant_b)
    with pytest.raises(WebSocketDisconnect) as exc:
        with client.websocket_connect(f"/api/v1/investigations/{RUN_ID}/stream") as ws:
            ws.receive_text()
    assert exc.value.code == 1008


def test_websocket_still_streams_an_owned_in_memory_run(
    setup_api, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, _ = setup_api
    investigate_mod._runs[RUN_ID] = {
        "run_id": RUN_ID,
        "tenant_id": str(TENANT_A),
        "status": "completed",
        "audit_log": [],
    }

    async def principal_for_tenant_a(_ws) -> TenantPrincipal:
        return TenantPrincipal(tenant_ids=frozenset({TENANT_A}), subject="test")

    monkeypatch.setattr(investigate_mod, "_ws_principal", principal_for_tenant_a)
    with client.websocket_connect(f"/api/v1/investigations/{RUN_ID}/stream") as ws:
        message = ws.receive_json()
    assert message["type"] == "done"
    assert message["status"] == "completed"


def test_websocket_replays_terminal_event_for_persisted_run(
    setup_api, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, state = setup_api
    state["runs"][(uuid.UUID(RUN_ID), TENANT_A)] = {
        "id": uuid.UUID(RUN_ID),
        "run_id": RUN_ID,
        "tenant_id": TENANT_A,
        "case_id": "case-persisted",
        "alert_summary": "Suspicious login",
        "raw_alert": {},
        "model_used": "local",
        "status": "completed",
        "error": None,
        "total_tokens": 0,
        "total_cost_usd": 0,
        "iterations": 0,
        "started_at": datetime(2026, 1, 1, tzinfo=UTC),
        "completed_at": datetime(2026, 1, 1, 0, 1, tzinfo=UTC),
    }

    async def principal_for_tenant_a(_ws) -> TenantPrincipal:
        return TenantPrincipal(tenant_ids=frozenset({TENANT_A}), subject="test")

    def unexpected_investigation(**_: Any):
        raise AssertionError("persisted runs must not start a new investigation")

    monkeypatch.setattr(investigate_mod, "_ws_principal", principal_for_tenant_a)
    monkeypatch.setattr(investigate_mod, "_investigate_stream", unexpected_investigation)

    with client.websocket_connect(f"/api/v1/investigations/{RUN_ID}/stream") as ws:
        message = ws.receive_json()

    assert message == {
        "type": "done",
        "case_id": "case-persisted",
        "status": "completed",
        "error": None,
    }


def test_websocket_does_not_restart_a_persisted_running_run(
    setup_api, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, state = setup_api
    state["runs"][(uuid.UUID(RUN_ID), TENANT_A)] = {
        "id": uuid.UUID(RUN_ID),
        "run_id": RUN_ID,
        "tenant_id": TENANT_A,
        "case_id": "case-persisted",
        "alert_summary": "Suspicious login",
        "raw_alert": {},
        "model_used": "local",
        "status": "running",
        "error": None,
        "total_tokens": 0,
        "total_cost_usd": 0,
        "iterations": 0,
        "started_at": datetime(2026, 1, 1, tzinfo=UTC),
        "completed_at": None,
    }

    async def principal_for_tenant_a(_ws) -> TenantPrincipal:
        return TenantPrincipal(tenant_ids=frozenset({TENANT_A}), subject="test")

    def unexpected_investigation(**_: Any):
        raise AssertionError("a persisted running run must not be duplicated")

    monkeypatch.setattr(investigate_mod, "_ws_principal", principal_for_tenant_a)
    monkeypatch.setattr(investigate_mod, "_investigate_stream", unexpected_investigation)
    with pytest.raises(WebSocketDisconnect) as exc:
        with client.websocket_connect(f"/api/v1/investigations/{RUN_ID}/stream") as ws:
            ws.receive_text()

    assert exc.value.code == 1013


def test_websocket_refuses_missing_run_without_starting_investigation(
    setup_api, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, _ = setup_api

    async def principal_for_tenant_a(_ws) -> TenantPrincipal:
        return TenantPrincipal(tenant_ids=frozenset({TENANT_A}), subject="test")

    def unexpected_investigation(**_: Any):
        raise AssertionError("an unknown run ID must not start an investigation")

    monkeypatch.setattr(investigate_mod, "_ws_principal", principal_for_tenant_a)
    monkeypatch.setattr(investigate_mod, "_investigate_stream", unexpected_investigation)
    with pytest.raises(WebSocketDisconnect) as exc:
        with client.websocket_connect(f"/api/v1/investigations/{RUN_ID}/stream") as ws:
            ws.receive_text()

    assert exc.value.code == 1008


def test_websocket_refuses_persisted_run_from_another_tenant(
    setup_api, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, state = setup_api
    state["runs"][(uuid.UUID(RUN_ID), TENANT_A)] = {
        "id": uuid.UUID(RUN_ID),
        "run_id": RUN_ID,
        "tenant_id": TENANT_A,
        "case_id": "case-private",
        "status": "completed",
    }
    state["tenant_id"] = TENANT_B

    async def principal_for_tenant_b(_ws) -> TenantPrincipal:
        return TenantPrincipal(tenant_ids=frozenset({TENANT_B}), subject="test")

    def unexpected_investigation(**_: Any):
        raise AssertionError("a foreign run ID must not start an investigation")

    monkeypatch.setattr(investigate_mod, "_ws_principal", principal_for_tenant_b)
    monkeypatch.setattr(investigate_mod, "_investigate_stream", unexpected_investigation)
    with pytest.raises(WebSocketDisconnect) as exc:
        with client.websocket_connect(f"/api/v1/investigations/{RUN_ID}/stream") as ws:
            ws.receive_text()

    assert exc.value.code == 1008


def test_websocket_preserves_explicit_adhoc_investigation(
    setup_api, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, _ = setup_api
    seen: list[dict[str, Any]] = []

    async def principal_for_tenant_a(_ws) -> TenantPrincipal:
        return TenantPrincipal(tenant_ids=frozenset({TENANT_A}), subject="test")

    async def fake_adhoc_stream(**kwargs: Any):
        seen.append(kwargs)
        yield {"type": "done", "case_id": kwargs["case_id"], "state": {}}

    monkeypatch.setattr(investigate_mod, "_ws_principal", principal_for_tenant_a)
    monkeypatch.setattr(investigate_mod, "_investigate_stream", fake_adhoc_stream)

    with client.websocket_connect(
        f"/api/v1/investigations/{RUN_ID}/stream?case_id=adhoc-case&alert_summary=adhoc-summary"
    ) as ws:
        message = ws.receive_json()

    assert message["type"] == "done"
    assert seen == [
        {
            "case_id": "adhoc-case",
            "alert_summary": "adhoc-summary",
            "raw_alert": {},
            "tenant_id": str(TENANT_A),
        }
    ]


@pytest.mark.asyncio
async def test_agent_run_polling_refuses_another_tenants_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        agent_runs_mod,
        "_runs",
        {RUN_ID: {"tenant_id": str(TENANT_A), "status": "completed"}},
    )
    principal = TenantPrincipal(tenant_ids=frozenset({TENANT_B}), subject="test")

    with pytest.raises(HTTPException) as exc:
        await agent_runs_mod.get_investigation(RUN_ID, principal)

    assert exc.value.status_code == 404


@pytest.mark.asyncio
async def test_agent_run_polling_hides_tenant_id_and_keeps_response_fields(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        agent_runs_mod,
        "_runs",
        {
            RUN_ID: {
                "tenant_id": str(TENANT_A),
                "status": "completed",
                "result": {"tenant_id": str(TENANT_A), "findings": ["one"]},
            }
        },
    )
    principal = TenantPrincipal(tenant_ids=frozenset({TENANT_A}), subject="test")

    response = await agent_runs_mod.get_investigation(RUN_ID, principal)

    assert response == {"status": "completed", "result": {"findings": ["one"]}}
