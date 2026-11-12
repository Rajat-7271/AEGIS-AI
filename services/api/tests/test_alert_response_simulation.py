"""Tenant- and run-bound forced-dry-run handoff for deterministic triage."""

from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest
from app.api.v1.endpoints import playbook_steps
from fastapi import HTTPException

pytestmark = pytest.mark.asyncio

TENANT = uuid.UUID("11111111-1111-1111-1111-111111111111")
OTHER_TENANT = uuid.UUID("22222222-2222-2222-2222-222222222222")
ALERT_ID = uuid.UUID("33333333-3333-3333-3333-333333333333")
RUN_ID = uuid.UUID("44444444-4444-4444-4444-444444444444")


class _Result:
    def __init__(self, value):
        self.value = value

    def scalar_one_or_none(self):
        return self.value


class _DB:
    def __init__(self, *, alert_tenant=TENANT, run_tenant=TENANT, proposal=True):
        self.alert = SimpleNamespace(
            id=ALERT_ID,
            tenant_id=alert_tenant,
            connector_type="crowdstrike",
            case_id=None,
            affected_hosts=["WIN-DC01"],
            entities=[],
            raw_event={},
        )
        self.run = SimpleNamespace(
            id=RUN_ID,
            tenant_id=run_tenant,
            case_id=str(ALERT_ID),
            model_used="kafka:auto_triage:deterministic",
        )
        self.event = SimpleNamespace(
            payload={"proposed_actions": [{"action_type": "isolate_host", "target": "WIN-DC01"}] if proposal else []}
        )

    async def execute(self, statement):
        sql = str(statement)
        if "FROM alerts" in sql:
            return _Result(self.alert if self.alert.tenant_id == TENANT else None)
        if "FROM investigation_runs" in sql:
            return _Result(self.run if self.run.tenant_id == TENANT else None)
        return _Result(self.event)


def _body(**overrides):
    fields = {
        "alert_id": ALERT_ID,
        "run_id": RUN_ID,
        "tenant_id": TENANT,
        "capability": "isolate_host",
        "target": "WIN-DC01",
        "confidence": 0.9,
    }
    fields.update(overrides)
    return playbook_steps.AlertResponseSimulationRequest(**fields)


async def test_simulation_is_forced_dry_run_and_bound_to_recorded_proposal(monkeypatch):
    monkeypatch.setenv("AISOC_AGENTS_SERVICE_TOKEN", "unit-token")
    monkeypatch.setattr(playbook_steps.actions_client, "vendors_for_capability", _vendors)
    calls = []

    async def dispatch(**kwargs):
        calls.append(kwargs)
        return {"mode": "dry_run", "result": {"status": "simulated", "summary": "host isolation preview"}}

    monkeypatch.setattr(playbook_steps.actions_client, "dispatch_live_action", dispatch)
    result = await playbook_steps.simulate_alert_response(_body(), None, _DB(), "unit-token")
    assert result["proposal_status"] == "proposed"
    assert result["status"] == "simulated"
    assert result["simulated"] is True
    assert result["executed"] is False
    assert calls[0]["dry_run"] is True
    assert calls[0]["tenant_id"] == str(TENANT)
    assert "auth_config" not in calls[0]


async def test_contradictory_action_success_is_not_reported_as_simulated(monkeypatch):
    monkeypatch.setenv("AISOC_AGENTS_SERVICE_TOKEN", "unit-token")
    monkeypatch.setattr(playbook_steps.actions_client, "vendors_for_capability", _vendors)

    async def report_success_even_in_dry_run(**_kwargs):
        return {"mode": "dry_run", "result": {"status": "succeeded", "summary": "unexpected"}}

    monkeypatch.setattr(playbook_steps.actions_client, "dispatch_live_action", report_success_even_in_dry_run)
    result = await playbook_steps.simulate_alert_response(_body(), None, _DB(), "unit-token")
    assert result["status"] == "failed"
    assert result["simulated"] is False
    assert result["executed"] is False


async def _vendors(_capability):
    return ["crowdstrike"]


async def test_cross_tenant_alert_is_rejected_before_actions_call(monkeypatch):
    monkeypatch.setenv("AISOC_AGENTS_SERVICE_TOKEN", "unit-token")
    calls = []

    async def dispatch(**kwargs):
        calls.append(kwargs)
        return {}

    monkeypatch.setattr(playbook_steps.actions_client, "dispatch_live_action", dispatch)
    with pytest.raises(HTTPException) as exc:
        await playbook_steps.simulate_alert_response(_body(), None, _DB(alert_tenant=OTHER_TENANT), "unit-token")
    assert exc.value.status_code == 404
    assert calls == []


async def test_run_must_be_tenant_owned_and_associated_with_the_alert(monkeypatch):
    monkeypatch.setenv("AISOC_AGENTS_SERVICE_TOKEN", "unit-token")
    with pytest.raises(HTTPException) as exc:
        await playbook_steps.simulate_alert_response(_body(), None, _DB(run_tenant=OTHER_TENANT), "unit-token")
    assert exc.value.status_code == 404


async def test_unproposed_action_or_unrelated_target_is_rejected(monkeypatch):
    monkeypatch.setenv("AISOC_AGENTS_SERVICE_TOKEN", "unit-token")
    with pytest.raises(HTTPException) as exc:
        await playbook_steps.simulate_alert_response(_body(target="OTHER-HOST"), None, _DB(), "unit-token")
    assert exc.value.status_code == 404
    with pytest.raises(HTTPException) as exc:
        await playbook_steps.simulate_alert_response(_body(), None, _DB(proposal=False), "unit-token")
    assert exc.value.status_code == 404


async def test_untrusted_caller_cannot_invoke_simulation(monkeypatch):
    monkeypatch.delenv("AISOC_AGENTS_SERVICE_TOKEN", raising=False)
    with pytest.raises(HTTPException) as exc:
        await playbook_steps.simulate_alert_response(_body(), None, _DB(), None)
    assert exc.value.status_code == 401
