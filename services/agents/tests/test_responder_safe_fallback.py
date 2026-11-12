"""A failed responder model must not invent disruptive response actions."""

from __future__ import annotations

import pytest

from app.investigator import responder_agent
from app.investigator.state import InvestigatorState


@pytest.mark.asyncio
async def test_responder_model_failure_returns_no_unsupported_actions(monkeypatch):
    monkeypatch.setattr(responder_agent, "resolve_model_alias", lambda _name: "test-model")
    monkeypatch.setattr(responder_agent, "make_chat_model", lambda *args, **kwargs: object())
    monkeypatch.setattr(responder_agent, "prompt_text", lambda _name: "system prompt")

    async def fail_model(*_args, **_kwargs):
        raise RuntimeError("provider unavailable")

    monkeypatch.setattr(responder_agent, "safe_ainvoke", fail_model)

    state = InvestigatorState(
        case_id="case-1",
        tenant_id="tenant-1",
        alert_summary="Suspicious PowerShell activity; compromise not confirmed.",
    )
    result = await responder_agent._llm_responder(state)

    assert result["recommended_actions"] == []
    assert result["containment_steps"] == []
    assert result["eradication_steps"] == []
    assert result["recovery_steps"] == []
    assert result["risk_level"] == "unknown"
    assert "analyst must review" in result["summary"].lower()
    decisions = [entry for entry in state.audit_log if entry.kind.value == "decision_reason"]
    assert decisions[-1].metadata["decision"] == "no_automated_action_plan"
