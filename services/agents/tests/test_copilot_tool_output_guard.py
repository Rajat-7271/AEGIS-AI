"""Copilot must never present unexecuted tool invocations as analysis."""

import json
import uuid

import httpx
import pytest
from app.api import copilot
from app.api.copilot import CALL_FAILED, _get_openai_reply, _looks_like_unexecuted_tool_call
from app.security.tenant_scope import TenantPrincipal, require_console_or_service_auth
from fastapi import FastAPI
from fastapi.testclient import TestClient


@pytest.mark.parametrize("endpoint", ["chat", "chat/stream"])
@pytest.mark.parametrize("answer", ["Review the timeline.", 'bash(command="whoami")'])
@pytest.mark.parametrize("openrouter", [True, False], ids=["openrouter", "litellm"])
def test_chat_round_trip(monkeypatch, endpoint, answer, openrouter):
    monkeypatch.delenv("LLM_BASE_URL", raising=False)
    if openrouter:
        base = "https://openrouter.ai/api/v1"
        model = "openai/test-model"
        monkeypatch.setenv("OPENAI_BASE_URL", base)
        monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    else:
        base = "http://gateway.test/v1"
        model = "aisoc-copilot"
        monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
        monkeypatch.setenv("LLM_GATEWAY_URL", base)
        monkeypatch.setenv("LITELLM_MASTER_KEY", "test-key")
    monkeypatch.setenv("AISOC_MODEL_PIN_COPILOT", model)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    principal = TenantPrincipal(tenant_ids=frozenset({uuid.uuid4()}))

    requests = []

    def complete(request):
        assert str(request.url) == f"{base}/chat/completions"
        assert request.headers["authorization"] == "Bearer test-key"
        payload = json.loads(request.content)
        requests.append(payload)
        reply = answer if len(requests) == 1 else "Check the alert's evidence and timestamps."
        content = json.dumps({"answer": reply}) if openrouter else reply
        return httpx.Response(200, json={"choices": [{"message": {"content": content}}]})

    client_class = httpx.AsyncClient
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kwargs: client_class(transport=httpx.MockTransport(complete), **kwargs))
    app = FastAPI()
    app.include_router(copilot.router)
    app.dependency_overrides[require_console_or_service_auth] = lambda: principal
    with TestClient(app) as client:
        question = "How should I review this alert?"
        response = client.post(f"/api/v1/copilot/{endpoint}", json={"message": question})

    assert response.status_code == 200
    assert len(requests) == 1
    assert [message["content"] for message in requests[0]["messages"] if message["role"] == "user"] == [question]
    assert requests[0]["model"] == model
    if openrouter:
        assert requests[0]["response_format"]["type"] == "json_schema"
        assert requests[0]["provider"] == {"require_parameters": True, "allow_fallbacks": False}
    else:
        assert requests[0]["num_retries"] == 0
        assert requests[0]["disable_fallbacks"] is True
    if endpoint == "chat":
        payload = response.json()
        source, reply = payload["source"], payload["reply"]["content"]
        conversation_id = payload["conversationId"]
    else:
        events = [json.loads(line) for line in response.text.splitlines()]
        source = events[0]["source"]
        reply = "".join(event.get("delta", "") for event in events)
        assert events[-1]["done"]
        conversation_id = events[-1]["conversationId"]
    if answer.startswith("bash"):
        assert source == "template"
        assert answer not in reply
    else:
        assert source == "llm"
        assert reply == answer

    follow_up = "What should I check next?"
    with TestClient(app) as client:
        response = client.post("/api/v1/copilot/chat", json={"conversationId": conversation_id, "message": follow_up})

    assert response.status_code == 200
    assert response.json()["conversationId"] == conversation_id
    assert response.json()["source"] == "llm"
    assert response.json()["reply"]["content"] == "Check the alert's evidence and timestamps."
    assert len(requests) == 2
    messages = requests[1]["messages"]
    assert [message["content"] for message in messages if message["role"] == "user"] == [question, follow_up]
    assert [message["content"] for message in messages if message["role"] == "assistant"] == ([answer] if source == "llm" else [])


@pytest.mark.parametrize(
    "content",
    [
        '<|tool_call_start|>query_system(hostname="host")<|tool_call_end|>',
        '<tool_call>bash(command="ls")</tool_call>',
        'bash(command="whoami")',
        'query_system(hostname="WORKSTATION-01")',
        '  query_system(query="alerts")',
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


@pytest.mark.parametrize(
    ("role", "source", "content", "excluded"),
    [
        ("assistant", None, copilot._fallback_reply(copilot.NO_MODEL), True),
        ("assistant", None, copilot._LEGACY_TOOL_FALLBACK, True),
        (
            "assistant",
            None,
            "I can't answer this: the configured model (test) did not return a reply.\n\n" + copilot._LEGACY_FAILURE_ENDING,
            True,
        ),
        ("assistant", None, "I can't answer this: the configured model is unknown to me.", False),
        ("assistant", "llm", copilot._LEGACY_TOOL_FALLBACK, False),
        ("user", None, copilot._LEGACY_TOOL_FALLBACK, False),
    ],
)
def test_legacy_fallback_filter(role, source, content, excluded):
    message = {"role": role, "content": content}
    if source is not None:
        message["source"] = source
    assert copilot._is_fallback_message(message) is excluded


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "response",
    [
        [],
        {"choices": []},
        {"choices": [{"message": "private-provider-detail"}]},
        {"error": {"message": "private-provider-detail"}},
        {"choices": [{"message": {"content": "private-provider-detail"}}]},
        {"choices": [{"message": {"content": '{"answer": ["private-provider-detail"]}'}}]},
        {"choices": [{"message": {"content": '{"answer": "Looks valid", "extra": "private-provider-detail"}'}}]},
        {"choices": [{"finish_reason": "tool_calls", "message": {"content": '{"answer": "Looks valid"}'}}]},
        400,
        401,
    ],
)
async def test_openrouter_unusable_response_fails_safely(monkeypatch, response):
    from app.llm import contract, factory
    from structlog.testing import capture_logs

    monkeypatch.setattr(factory, "resolve_model_alias", lambda role: "openai/test-model")
    monkeypatch.setattr(factory, "resolve_api_key", lambda model: "test-key")
    monkeypatch.setattr(factory, "chat_completions_url", lambda model: "https://openrouter.ai/api/v1/chat/completions")
    calls = []

    async def fake_completion(**kwargs):
        calls.append(kwargs)
        if isinstance(response, int):
            request = httpx.Request("POST", kwargs["url"])
            raise httpx.HTTPStatusError("private-provider-detail", request=request, response=httpx.Response(response, request=request))
        return response

    monkeypatch.setattr(contract, "safe_chat_completions_request", fake_completion)
    with capture_logs() as logs:
        reply, source, reason = await _get_openai_reply({"messages": []}, "Review this alert.")
    assert (source, reason) == ("template", CALL_FAILED)
    assert len(calls) == 1
    assert "private-provider-detail" not in reply
    assert "private-provider-detail" not in str(logs)
    if isinstance(response, int):
        assert f"HTTP {response}" in reply


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "message",
    [
        {"content": 'bash(command="whoami")'},
        {"content": 'query_system(hostname="host")'},
        {"content": '<|tool_call_start|>bash(command="ls")<|tool_call_end|>'},
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


@pytest.mark.asyncio
async def test_llm_prompt_includes_current_question_once(monkeypatch):
    from app.llm import contract, factory

    monkeypatch.setattr(factory, "resolve_model_alias", lambda role: "test-model")
    monkeypatch.setattr(factory, "resolve_api_key", lambda model: "test-key")
    monkeypatch.setattr(factory, "chat_completions_url", lambda model: "https://example.test/chat")
    captured = {}

    async def fake_completion(**kwargs):
        captured["messages"] = kwargs["messages"]
        return {"choices": [{"message": {"content": "Understood."}}]}

    monkeypatch.setattr(contract, "safe_chat_completions_request", fake_completion)
    reply, source, reason = await _get_openai_reply(
        {
            "messages": [
                {"role": "user", "content": "Previous question"},
                {"role": "assistant", "content": "Unavailable", "source": "template"},
            ]
        },
        "Current question",
    )
    assert (reply, source, reason) == ("Understood.", "llm", None)
    assert all(message["role"] != "assistant" for message in captured["messages"])
    assert [m["content"] for m in captured["messages"] if m["role"] == "user"] == ["Previous question", "Current question"]
