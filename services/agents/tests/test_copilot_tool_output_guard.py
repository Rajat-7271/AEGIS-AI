"""Copilot must never present unexecuted tool invocations as analysis."""

import pytest

from app.api.copilot import CALL_FAILED, _get_openai_reply, _looks_like_unexecuted_tool_call


@pytest.mark.parametrize(
    "content",
    [
        "<|tool_call_start|>query_system(hostname=\"host\")<|tool_call_end|>",
        "<tool_call>bash(command=\"ls\")</tool_call>",
        "bash(command=\"whoami\")",
        "query_system(hostname=\"WORKSTATION-01\")",
        "  query_system(query=\"alerts\")",
    ],
)
def test_reject_unexecuted_tool_invocation(content: str) -> None:
    assert _looks_like_unexecuted_tool_call(content)


@pytest.mark.parametrize(
    "content",
    [
        "I cannot query live telemetry from this chat.",
        "Use the Alerts view to inspect actual events.",
        "The string bash(command= is an example of a tool invocation.",
        "Here is how to investigate a suspicious login.",
    ],
)
def test_preserve_normal_analyst_responses(content: str) -> None:
    assert not _looks_like_unexecuted_tool_call(content)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "message",
    [
        {"content": "bash(command=\"whoami\")"},
        {"content": "query_system(hostname=\"host\")"},
        {"content": "<|tool_call_start|>bash(command=\"ls\")<|tool_call_end|>"},
        {"content": None, "tool_calls": [{"id": "call_1", "type": "function"}]},
        {"content": "", "function_call": {"name": "query_system"}},
    ],
)
async def test_model_tool_output_becomes_labelled_fallback(monkeypatch, message):
    from app.llm import contract, factory

    monkeypatch.setattr(factory, "resolve_model_alias", lambda role: "test-model")
    monkeypatch.setattr(factory, "resolve_api_key", lambda model: "test-key")
    monkeypatch.setattr(factory, "chat_completions_url", lambda model: "https://example.test/chat")

    async def fake_completion(**kwargs):
        return {"choices": [{"message": message}]}

    monkeypatch.setattr(contract, "safe_chat_completions_request", fake_completion)
    reply, source, reason = await _get_openai_reply({"messages": []}, "Inspect host")
    assert source == "template"
    assert reason == CALL_FAILED
    assert "cannot query live security telemetry" in reply


@pytest.mark.asyncio
async def test_normal_model_response_is_preserved(monkeypatch):
    from app.llm import contract, factory

    monkeypatch.setattr(factory, "resolve_model_alias", lambda role: "test-model")
    monkeypatch.setattr(factory, "resolve_api_key", lambda model: "test-key")
    monkeypatch.setattr(factory, "chat_completions_url", lambda model: "https://example.test/chat")

    async def fake_completion(**kwargs):
        return {"choices": [{"message": {"content": "Review the alert timeline first."}}]}

    monkeypatch.setattr(contract, "safe_chat_completions_request", fake_completion)
    reply, source, reason = await _get_openai_reply({"messages": []}, "Investigate alert")
    assert (reply, source, reason) == ("Review the alert timeline first.", "llm", None)
