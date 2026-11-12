"""Copilot must never present unexecuted tool invocations as analysis."""

import pytest

from app.api.copilot import _looks_like_unexecuted_tool_call


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
