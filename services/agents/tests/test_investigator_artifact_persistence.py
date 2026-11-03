"""Focused persistence tests for InvestigatorOrchestrator report artifacts."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock
from uuid import UUID

import pytest

_AGENTS_ROOT = Path(__file__).resolve().parents[1]
if str(_AGENTS_ROOT) not in sys.path:
    sys.path.insert(0, str(_AGENTS_ROOT))

from app.investigator import orchestrator as investigator_orchestrator  # noqa: E402
from app.investigator.state import InvestigatorState  # noqa: E402

TENANT_ID = UUID("aaaaaaaa-0000-0000-0000-00000000000a")
RUN_ID = UUID("78191af6-6f87-4256-8288-31b583c71635")
REPORT_MD = "# Incident report"
REPORT_HTML = "<html><body>Incident report</body></html>"


class _FixedGraph:
    def __init__(self, state: InvestigatorState) -> None:
        self.state = state

    async def ainvoke(self, _initial: dict[str, Any]) -> dict[str, Any]:
        return self.state.to_dict()

    async def astream(self, _initial: dict[str, Any]):
        yield {"report_writer": self.state.to_dict()}


class _FixedTracker:
    async def __aenter__(self) -> _FixedTracker:
        return self

    async def __aexit__(self, *_: Any) -> None:
        return None

    def summary(self) -> dict[str, Any]:
        return {}


def _state(*, report_html: str) -> InvestigatorState:
    return InvestigatorState(
        case_id="case-123",
        alert_summary="Suspicious login",
        tenant_id=str(TENANT_ID),
        status="completed",
        report_md=REPORT_MD,
        report_html=report_html,
    )


def _prepare(
    monkeypatch: pytest.MonkeyPatch,
    *,
    report_html: str,
) -> tuple[investigator_orchestrator.InvestigatorOrchestrator, AsyncMock]:
    artifacts = AsyncMock()
    monkeypatch.setattr(
        investigator_orchestrator,
        "prefetch_context_bundle_dict",
        AsyncMock(return_value={}),
    )
    monkeypatch.setattr(
        investigator_orchestrator, "CostTracker", lambda **_: _FixedTracker()
    )
    monkeypatch.setattr(
        investigator_orchestrator.ledger, "start_run", AsyncMock(return_value=TENANT_ID)
    )
    monkeypatch.setattr(investigator_orchestrator.ledger, "record_event", AsyncMock())
    monkeypatch.setattr(
        investigator_orchestrator.ledger, "record_artifact", artifacts
    )
    monkeypatch.setattr(investigator_orchestrator.ledger, "complete_run", AsyncMock())
    monkeypatch.setattr(investigator_orchestrator, "_apply_groundedness", lambda _: None)

    instance = investigator_orchestrator.InvestigatorOrchestrator.__new__(
        investigator_orchestrator.InvestigatorOrchestrator
    )
    instance._graph = _FixedGraph(_state(report_html=report_html))
    return instance, artifacts


@pytest.mark.asyncio
async def test_run_persists_html_artifact_with_run_and_tenant(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    orchestrator, artifacts = _prepare(monkeypatch, report_html=REPORT_HTML)

    await orchestrator.run(
        "case-123", "Suspicious login", tenant_id=str(TENANT_ID), run_id=RUN_ID
    )

    html_artifacts = [
        call.kwargs for call in artifacts.await_args_list if call.kwargs["kind"] == "report_html"
    ]
    assert html_artifacts == [
        {
            "run_id": RUN_ID,
            "tenant_id": TENANT_ID,
            "kind": "report_html",
            "content": REPORT_HTML,
        }
    ]


@pytest.mark.asyncio
async def test_stream_persists_html_artifact_with_run_and_tenant(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    orchestrator, artifacts = _prepare(monkeypatch, report_html=REPORT_HTML)

    events = [
        event
        async for event in orchestrator.stream(
            "case-123", "Suspicious login", tenant_id=str(TENANT_ID), run_id=RUN_ID
        )
    ]

    html_artifacts = [
        call.kwargs for call in artifacts.await_args_list if call.kwargs["kind"] == "report_html"
    ]
    assert html_artifacts == [
        {
            "run_id": RUN_ID,
            "tenant_id": TENANT_ID,
            "kind": "report_html",
            "content": REPORT_HTML,
        }
    ]
    assert events[-1]["type"] == "done"


@pytest.mark.parametrize("streaming", [False, True], ids=["run", "stream"])
@pytest.mark.asyncio
async def test_missing_html_skips_html_artifact(
    monkeypatch: pytest.MonkeyPatch, streaming: bool
) -> None:
    orchestrator, artifacts = _prepare(monkeypatch, report_html="")

    if streaming:
        events = [
            event
            async for event in orchestrator.stream(
                "case-123", "Suspicious login", tenant_id=str(TENANT_ID), run_id=RUN_ID
            )
        ]
        assert events[-1]["type"] == "done"
    else:
        await orchestrator.run(
            "case-123", "Suspicious login", tenant_id=str(TENANT_ID), run_id=RUN_ID
        )

    assert [call.kwargs["kind"] for call in artifacts.await_args_list] == ["report_md"]
