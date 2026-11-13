"""
Copilot chat API — persistent conversation history.

Endpoints (all under ``/api/v1/copilot``):

    GET  /conversations             — list the last N conversations
    GET  /conversations/{id}        — retrieve a single conversation
    POST /chat                      — one-shot chat (creates / continues conv.)
    POST /chat/stream               — streaming NDJSON variant

When no model answers, the reply says so and names which of the two
reasons applies — nothing is configured, or what is configured did not
return. It does not describe the tenant's data, because nothing read it.
"""

from __future__ import annotations

import json
import re
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any, Literal
from urllib.parse import urlsplit

import httpx
import structlog
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from app.api import conversation_store
from app.api.copilot_grounding import ground_answer, sources_from_context
from app.security.tenant_scope import (
    TenantPrincipal,
    TenantScopeError,
    require_console_or_service_auth,
    resolve_scoped_tenant,
)

logger = structlog.get_logger()

#: Default-deny. The console reaches this router directly through a Next
#: rewrite carrying the first-party access token, so the guard resolves
#: either that session or a trusted service declaring the tenant it acts
#: for — a bearer-token-only scheme would lock the browser out.
router = APIRouter(prefix="/api/v1/copilot", tags=["copilot"], dependencies=[Depends(require_console_or_service_auth)])


# ---------------------------------------------------------------------------
# Shapes
# ---------------------------------------------------------------------------


class CopilotMessage(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    role: str  # "user" | "assistant"
    content: str
    timestamp: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())


class CopilotChatRequest(BaseModel):
    message: str
    conversationId: str | None = None
    context: dict[str, Any] | None = None


class CopilotChatResponse(BaseModel):
    conversationId: str
    reply: CopilotMessage
    #: ``llm`` when a model produced the reply, ``template`` when this service
    #: fell back to a canned paragraph (no API key, or the call failed).
    #: The console must label a ``template`` reply rather than presenting it as
    #: analysis of the user's environment.
    source: Literal["llm", "template"] = "llm"
    #: Why no model answered, when ``source`` is ``template``. Additive
    #: rather than a third ``source`` value, so existing clients branching
    #: on ``template`` keep working while a new one can tell "nothing is
    #: configured" from "what is configured did not answer" (issue #1275).
    template_reason: Literal["no_model_configured", "model_call_failed"] | None = None
    notice: str | None = None
    #: Which factual claims in `reply` cite a record, and which cite
    #: nothing (parity 3.6). The console renders the label beside the
    #: answer: an analyst has no other way to tell a claim drawn from the
    #: evidence from one the model produced because it sounded right.
    grounding: dict[str, Any] | None = None


class CopilotConversation(BaseModel):
    id: str
    title: str
    updatedAt: str
    messageCount: int


# ---------------------------------------------------------------------------
# Conversation store
#
# Tenant-scoped and persistent. This said "in-memory (demo: resets on
# restart)" long after `conversation_store` took both a tenant and a
# database, which is the kind of stale comment that makes a reader
# distrust the ones that are true.
# ---------------------------------------------------------------------------


def _tenant_of(principal: TenantPrincipal) -> uuid.UUID:
    """The one tenant this request may read and write.

    Conversations lived in a module-level dict keyed by conversation id with
    no tenant anywhere, and the list and fetch handlers bound no principal at
    all — so `GET /conversations` returned every tenant's conversations to
    whoever asked, and `GET /conversations/{id}` returned any conversation to
    anyone holding its id. A copilot conversation carries the analyst's
    question, which names hosts and users, and the model's answer, which
    quotes the evidence it was grounded on.
    """
    try:
        return resolve_scoped_tenant(principal)
    except TenantScopeError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc


#: Why no model answered. These are two different operator problems and
#: the old code could not tell them apart (issue #1275).
NO_MODEL = "no_model_configured"
CALL_FAILED = "model_call_failed"

# OpenRouter's free endpoint for this model does not support response_format.
_NEMOTRON_ULTRA_FREE = "nvidia/nemotron-3-ultra-550b-a55b:free"

_LEGACY_TOOL_FALLBACK = (
    "I cannot query live security telemetry from this chat response. "
    "Open the Alerts or Explore view to inspect actual events, "
    "then share the relevant findings for analysis."
)
_LEGACY_FAILURE_ENDING = (
    "This is a model or gateway problem, not a missing credential — a model is configured. "
    "On a CPU-only deployment the usual cause is contention with the auto-triage backlog, "
    "which holds the same local model. Retrying usually works; if it does not, check the "
    "model service's own logs."
)


def _fallback_reply(reason: str, *, model: str | None = None, detail: str | None = None) -> str:
    """What to say when no model answered.

    This used to return one of five rotating paragraphs asserting findings
    about an estate it had never seen — "this IP was seen in 3 other
    alerts", "the attacker dwell time appears short (< 2 hours)", "multiple
    failed authentications followed by a successful login from an unusual
    geolocation". None of it was computed from anything. The reporter hit
    exactly that: a ransomware alert described back to them as
    "credential-access activity ... LOLBin pattern", because the function
    ignored its argument and returned the next item in the cycle.

    A canned paragraph that reads like analysis is worse than no answer,
    and the console appending a disclaimer underneath does not fix the
    body. So the reply is now the explanation, and it makes no claim about
    the tenant's data.
    """
    if reason == NO_MODEL:
        return (
            "I can't answer this: no language model is configured for this deployment.\n\n"
            "Nothing about your alerts, cases or detections was looked at, so treat this as "
            "an unanswered question rather than a finding.\n\n"
            "To enable the copilot, configure a model — either a hosted provider key or the "
            "bundled local model — and ask again."
        )

    named = f" ({model})" if model else ""
    because = f"\n\nDiagnostic: {detail}" if detail else ""
    return (
        f"Copilot could not produce an answer using the configured model{named}.{because}\n\n"
        "Treat this as an unanswered question rather than a finding."
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _title_from_message(msg: str) -> str:
    return msg[:60] + ("…" if len(msg) > 60 else "")


def _notice_for(reason: str | None) -> str | None:
    """The one-line banner the console puts above a template reply.

    One string served both fallback conditions and ended "Configure an LLM
    key to get a real investigation". On a deployment running the bundled
    local model that sentence names a credential the deployment does not
    use, so an operator whose model had merely timed out was sent to fix
    something that was not broken.
    """
    if reason == NO_MODEL:
        return "No language model is configured, so nothing answered this question. This is not analysis of your environment."
    if reason == CALL_FAILED:
        return "Copilot could not produce an answer for this question."
    return None


def _is_fallback_message(message: dict[str, Any]) -> bool:
    if message["role"] != "assistant":
        return False
    if message.get("source") is not None:
        return message["source"] == "template"
    content = message["content"]
    return content in (_LEGACY_TOOL_FALLBACK, _fallback_reply(NO_MODEL)) or (
        content.startswith("I can't answer this: the configured model") and content.endswith(_LEGACY_FAILURE_ENDING)
    )


def _is_general_knowledge_question(question: str, context: dict[str, Any] | None) -> bool:
    """Only exempt clearly educational questions without tenant evidence.

    An explicit alert/case context or estate-specific wording must retain
    the uncited-evidence warning, even when the question mentions ATT&CK.
    """
    if sources_from_context(context):
        return False
    q = question.strip().lower()
    if re.search(
        r"\b(my|our|this|these|current|actual)\s+(alerts?|hosts?|devices?|network|environment|cases?|incidents?|logs?|events?)\b", q
    ):
        return False
    return bool(
        re.match(
            r"^(?:please\s+)?(?:explain|define|describe|what\s+is|what\s+are|"
            r"how\s+does|how\s+do|which\s+windows\s+event\s+ids|"
            r"what\s+windows\s+event\s+ids|list\s+(?:the\s+)?(?:most\s+important\s+)?windows\s+event\s+ids)\b",
            q,
        )
    )


def _ground_copilot_reply(reply: str, question: str, context: dict[str, Any] | None) -> dict[str, Any] | None:
    """Do not treat general reference terms as uncited tenant findings."""
    if _is_general_knowledge_question(question, context):
        return None
    return ground_answer(reply, sources_from_context(context)).as_dict()


def _normalize_copilot_markdown(content: str) -> str:
    """Repair model-escaped Markdown tables without touching code or paths."""
    result: list[str] = []
    pending_blank: list[str] = []
    in_fence = False
    previous_table = False
    for line in content.splitlines(keepends=True):
        stripped = line.lstrip()
        if stripped.startswith(("```", "~~~")):
            in_fence = not in_fence
        if not in_fence and not stripped.startswith(("```", "~~~")):
            if re.match(r"^\\#{1,6}\s", stripped):
                line = line.replace(r"\#", "#", 6)
            elif re.match(r"^\\-{3,}\s*$", stripped):
                line = line.replace(r"\-", "-")
            elif stripped.startswith(r"\|") and stripped.count(r"\|") >= 2:
                line = line.replace(r"\|", "|").replace(r"\*", "*")
            elif stripped.startswith(r"\`") and stripped.count(r"\`") >= 2:
                line = line.replace(r"\`", "`")
        is_table = not in_fence and line.lstrip().startswith("|") and line.count("|") >= 3
        if not line.strip() and not in_fence:
            pending_blank.append(line)
            continue
        if pending_blank:
            if not (previous_table and is_table):
                result.extend(pending_blank)
            pending_blank.clear()
        result.append(line)
        previous_table = is_table
    result.extend(pending_blank)
    return "".join(result)


def _looks_like_unexecuted_tool_call(content: str) -> bool:
    """Reject tool invocation syntax, not ordinary discussion of commands."""
    if any(marker in content for marker in ("<|tool_call_start|>", "<|tool_call_end|>", "<tool_call>", "</tool_call>")):
        return True
    # Some providers return an invocation as plain text rather than structured
    # tool_calls. Do not show these as if an operation actually ran.
    return bool(re.search(r"(?m)^\s*`*(?:bash|query_system)\s*\(\s*(?:command|hostname|query)\s*=", content))


async def _get_openai_reply(
    conversation: dict[str, Any],
    user_message: str,
) -> tuple[str, str, str | None]:
    """Return ``(reply_text, source, reason)``.

    ``source`` is ``llm`` or ``template``; ``reason`` is ``None`` on the
    model path and otherwise names *why* no model answered.

    The caller must surface ``template`` to the user. This function silently
    returned a canned paragraph as a normal 200 whenever the key was missing or
    any exception fired, so an analyst read "this IP was seen in 3 other
    alerts" as real analysis of their environment. The frontend had an honest
    fallback of its own that never fired, because the backend reported success.

    Keep missing configuration distinct from a failed or unusable completion.
    """
    from app.llm.contract import safe_chat_completions_request
    from app.llm.factory import chat_completions_url, resolve_api_key, resolve_model_alias
    from app.llm.routing import at_bundled_gateway, is_gateway_alias, resolve_base_url

    model = None
    try:
        model = resolve_model_alias("copilot")
        api_key = resolve_api_key(model)
        if not api_key:
            return _fallback_reply(NO_MODEL), "template", NO_MODEL

        url = chat_completions_url(model)
        openrouter = urlsplit(url).hostname in {"openrouter.ai", "eu.openrouter.ai"}
        use_json_schema = openrouter and model != _NEMOTRON_ULTRA_FREE
        options: dict[str, Any] = {}
        if openrouter:
            if is_gateway_alias(model):
                detail = "Set AISOC_MODEL_PIN_COPILOT to an OpenRouter model ID that supports structured outputs."
                return _fallback_reply(CALL_FAILED, model=model, detail=detail), "template", CALL_FAILED
            options["provider"] = {"require_parameters": True, "allow_fallbacks": False}
        elif at_bundled_gateway(resolve_base_url(model)):
            # Request-level LiteLLM router controls. The running gateway version
            # and any upstream provider retries are outside this client's control.
            options = {"num_retries": 0, "disable_fallbacks": True}

        if use_json_schema:
            options["response_format"] = {
                "type": "json_schema",
                "json_schema": {
                    "name": "copilot_reply",
                    "strict": True,
                    "schema": {
                        "type": "object",
                        "properties": {"answer": {"type": "string"}},
                        "required": ["answer"],
                        "additionalProperties": False,
                    },
                },
            }

        messages: list[dict[str, str]] = [
            {
                "role": "system",
                "content": (
                    "You are AEGIS AI Copilot, the AI security operations assistant built into AEGIS AI. "
                    "Help analysts investigate alerts, correlate events, and respond to threats. "
                    "Be concise, technical, and actionable. Reference MITRE ATT&CK techniques "
                    "when relevant. Format recommendations as numbered steps when appropriate. "
                    "You cannot execute shell commands or query live hosts through this chat. "
                    "Never emit tool-call syntax or claim to have run tools. "
                    "If current telemetry is unavailable, say so and explain how to inspect it. "
                    "Answer general questions directly and ground any claims about the environment in supplied evidence. "
                    "Use normal Markdown headings and tables without escaping punctuation outside code blocks. "
                    "Preserve literal backslashes in commands and fenced code. "
                    "For Windows PowerShell logging, distinguish Event ID 4103 (Module Logging: pipeline execution details) "
                    "from Event ID 4104 (Script Block Logging: script block content). "
                    "They are not script-block start/end events. Do not invent event fields, "
                    "fixed truncation limits, guaranteed deobfuscation, or assert that every execution is logged. "
                    "When exact event semantics are uncertain, state the uncertainty and recommend "
                    "checking Microsoft documentation or the actual event schema. "
                    "Do not guess MITRE ATT&CK technique IDs or names. If uncertain, omit the mapping "
                    "and say it requires verification against the official ATT&CK catalog. "
                    "Event ID 4672 indicates special privileges assigned to a new logon; it alone "
                    "does not establish malicious privilege escalation. Correlate Windows logon "
                    "events using both the computer and logon ID, not logon ID alone across hosts. "
                    "For detection queries, use valid syntax for the named platform, and do not "
                    "invent a table name or claim that a heuristic proves an attack. "
                    "Use consistently numbered Markdown lists rather than mixing 1. and 1) markers. "
                    "For code fences, place the language tag alone on the opening fence line, "
                    "followed by a newline before code."
                    + (" Return the user-facing answer in the JSON field answer." if use_json_schema else "")
                ),
            }
        ]
        for m in conversation.get("messages", [])[-10:]:  # last 10 for context
            if _is_fallback_message(m):
                continue
            messages.append({"role": m["role"], "content": m["content"]})
        messages.append({"role": "user", "content": user_message})

        body = await safe_chat_completions_request(
            api_key=api_key,
            model=model,
            messages=messages,
            url=url,
            max_tokens=1024,
            **options,
        )
        if not isinstance(body, dict):
            raise ValueError("Invalid completion envelope")
        if body.get("error") is not None:
            return _fallback_reply(CALL_FAILED, model=model, detail="The provider returned an error response."), "template", CALL_FAILED
        choices = body.get("choices")
        if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
            raise ValueError("Invalid completion choices")
        choice = choices[0]
        message = choice.get("message")
        if not isinstance(message, dict):
            raise ValueError("Invalid completion message")
        content = message.get("content")
        attempted_tool = (
            message.get("tool_calls")
            or message.get("function_call")
            or choice.get("finish_reason") in ("tool_calls", "function_call")
            or (isinstance(content, str) and _looks_like_unexecuted_tool_call(content))
        )
        if use_json_schema and isinstance(content, str) and content.strip() and not attempted_tool:
            parsed = json.loads(content)
            content = parsed["answer"] if isinstance(parsed, dict) and parsed.keys() == {"answer"} else None
        if attempted_tool or (isinstance(content, str) and _looks_like_unexecuted_tool_call(content)):
            logger.warning("copilot.unexecuted_tool_call", model=model)
            detail = "The model attempted to use a tool. Copilot chat cannot query live security telemetry."
        elif isinstance(content, str) and content.strip():
            return _normalize_copilot_markdown(content), "llm", None
        else:
            detail = "The model returned no usable answer."
    except Exception as exc:
        # Provider exceptions can contain URLs, credentials, or prompt data.
        detail = f"HTTP {exc.response.status_code}" if isinstance(exc, httpx.HTTPStatusError) else type(exc).__name__
        logger.warning("copilot.openai_error", error=detail, model=model)
    return _fallback_reply(CALL_FAILED, model=model, detail=detail), "template", CALL_FAILED


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/conversations")
async def list_conversations(
    limit: int = 20,
    principal: TenantPrincipal = Depends(require_console_or_service_auth),
) -> dict[str, Any]:
    """This tenant's conversations, newest first."""
    conversations = await conversation_store.list_conversations(tenant_id=_tenant_of(principal), limit=limit)
    return {"conversations": [c.summary() for c in conversations]}


@router.get("/conversations/{conversation_id}")
async def get_conversation(
    conversation_id: str,
    principal: TenantPrincipal = Depends(require_console_or_service_auth),
) -> dict[str, Any]:
    """One conversation, if it belongs to this tenant.

    404 rather than the previous `{"title": "Not found", "messages": []}`
    body with a 200. A 200 saying "not found" is a shape no client can
    branch on, and it made "this id does not exist" and "this id is
    somebody else's" look the same as a real empty conversation.
    """
    conversation = await conversation_store.get_conversation(tenant_id=_tenant_of(principal), conversation_id=conversation_id)
    if conversation is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No such conversation.")
    return conversation.full()


@router.post("/chat", response_model=CopilotChatResponse)
async def chat(
    req: CopilotChatRequest,
    principal: TenantPrincipal = Depends(require_console_or_service_auth),
) -> CopilotChatResponse:
    tenant_id = _tenant_of(principal)
    now = datetime.now(UTC).isoformat()

    # Read the existing turns under the tenant predicate, so a caller naming
    # another tenant's conversation id gets a new conversation of their own
    # rather than that one's history as model context.
    existing = (
        await conversation_store.get_conversation(tenant_id=tenant_id, conversation_id=req.conversationId) if req.conversationId else None
    )

    user_msg: dict[str, Any] = {
        "id": str(uuid.uuid4()),
        "role": "user",
        "content": req.message,
        "timestamp": now,
    }

    history = {"messages": list(existing.messages) if existing else []}
    reply_text, reply_source, reply_reason = await _get_openai_reply(history, req.message)

    assistant_msg: dict[str, Any] = {
        "id": str(uuid.uuid4()),
        "role": "assistant",
        "content": reply_text,
        "source": reply_source,
        "timestamp": datetime.now(UTC).isoformat(),
    }

    # Both turns in one append, so two tabs on the same conversation cannot
    # drop each other's messages the way a read-modify-write would.
    stored = await conversation_store.append_messages(
        tenant_id=tenant_id,
        conversation_id=existing.id if existing else None,
        user_id=None,
        title=existing.title if existing else _title_from_message(req.message),
        new_messages=[user_msg, assistant_msg],
    )

    # Grade the answer against what it was given, and say so either way.
    # A template reply is not graded: it asserts nothing about this
    # estate, and labelling generic guidance "uncited" would put a
    # warning where there is no claim to warn about.
    grounding = _ground_copilot_reply(reply_text, req.message, req.context) if reply_source == "llm" else None

    return CopilotChatResponse(
        conversationId=stored.id,
        reply=CopilotMessage(**assistant_msg),
        source=reply_source,
        template_reason=reply_reason,
        grounding=grounding,
        notice=_notice_for(reply_reason),
    )


@router.post("/chat/stream")
async def chat_stream(
    req: CopilotChatRequest,
    principal: TenantPrincipal = Depends(require_console_or_service_auth),
) -> StreamingResponse:
    """Stream a chat reply as NDJSON deltas."""

    tenant_id = _tenant_of(principal)
    now = datetime.now(UTC).isoformat()

    existing = (
        await conversation_store.get_conversation(tenant_id=tenant_id, conversation_id=req.conversationId) if req.conversationId else None
    )

    user_msg: dict[str, Any] = {
        "id": str(uuid.uuid4()),
        "role": "user",
        "content": req.message,
        "timestamp": now,
    }
    history = {"messages": list(existing.messages) if existing else []}

    reply_text, reply_source, reply_reason = await _get_openai_reply(history, req.message)
    msg_id = str(uuid.uuid4())
    assistant_msg: dict[str, Any] = {
        "id": msg_id,
        "role": "assistant",
        "content": reply_text,
        "source": reply_source,
        "timestamp": datetime.now(UTC).isoformat(),
    }

    # Persisted before the stream opens, not inside the generator. A client
    # that disconnects mid-stream used to leave the assistant turn unwritten
    # while the user's question had already been appended, so the next
    # request fed the model a conversation ending in an unanswered question.
    # The reply is fully computed by this point, so there is nothing to wait
    # for.
    stored = await conversation_store.append_messages(
        tenant_id=tenant_id,
        conversation_id=existing.id if existing else None,
        user_id=None,
        title=existing.title if existing else _title_from_message(req.message),
        new_messages=[user_msg, assistant_msg],
    )

    async def _stream() -> AsyncIterator[bytes]:
        # Provenance first: a consumer must be able to label the answer before
        # it starts rendering tokens, not after.
        yield (
            json.dumps(
                {
                    "source": reply_source,
                    "template_reason": reply_reason,
                    "notice": _notice_for(reply_reason),
                    "delta": "",
                    "done": False,
                }
            )
            + "\n"
        ).encode()
        yield (json.dumps({"delta": reply_text, "done": False}) + "\n").encode()

        yield (
            json.dumps(
                {
                    "done": True,
                    "conversationId": stored.id,
                    "messageId": msg_id,
                }
            )
            + "\n"
        ).encode()

    return StreamingResponse(_stream(), media_type="application/x-ndjson")
