"""Regression coverage for preserving original alert evidence in case investigations."""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace

import pytest

from app.api.v1.endpoints.cases import _investigation_evidence


class _Result:
    def __init__(self, *, row=None, rows=None):
        self._row = row
        self._rows = rows or []

    def fetchone(self):
        return self._row

    def fetchall(self):
        return self._rows


class _DB:
    def __init__(self, case_row, alert_rows):
        self._results = iter([
            _Result(row=case_row),
            _Result(rows=alert_rows),
        ])

    async def execute(self, *_args, **_kwargs):
        return next(self._results)


@pytest.mark.asyncio
async def test_case_investigation_evidence_keeps_original_raw_event_and_alert_metadata():
    observed_at = datetime(2026, 11, 7, 10, 0, tzinfo=UTC)
    raw_event = {
        "process": {"name": "powershell.exe", "command_line": "powershell -enc ..."},
        "download": {"url": "https://example.invalid/payload"},
        "full_log": "original connector log",
    }
    case_row = SimpleNamespace(
        title="Suspicious PowerShell execution",
        description="Analyst-created case description",
        severity="high",
        alert_ids=["alert-1"],
    )
    alert_row = SimpleNamespace(
        id="alert-1",
        title="Encoded PowerShell command",
        description="Encoded command observed",
        severity="high",
        confidence=0.91,
        status="new",
        connector_type="endpoint",
        external_id="vendor-123",
        mitre_techniques=["T1059.001"],
        entities={"host": "workstation-7"},
        raw_event=raw_event,
        created_at=observed_at,
    )

    summary, evidence = await _investigation_evidence(
        _DB(case_row, [alert_row]),
        "case-1",
        "tenant-1",
    )

    assert "Suspicious PowerShell execution" in summary
    assert evidence["alert_count"] == 1
    assert evidence["alerts_included"] == 1
    assert evidence["truncated"] is False
    alert = evidence["alerts"][0]
    assert alert["raw_event"] == raw_event
    assert alert["entities"] == {"host": "workstation-7"}
    assert alert["mitre_techniques"] == ["T1059.001"]
    assert alert["vendor_id"] == "vendor-123"
    assert alert["observed_at"] == observed_at.isoformat()
