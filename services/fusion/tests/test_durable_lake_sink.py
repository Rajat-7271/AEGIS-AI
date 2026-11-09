"""Fail-closed durable lake sink characterization with a fake ClickHouse client."""
from __future__ import annotations

import pytest

from app.services.durable_lake_sink import DurableLakeSink, LakePersistenceError

pytestmark = pytest.mark.asyncio

TENANT = "11111111-1111-4111-8111-111111111111"
EVENT = "22222222-2222-4222-8222-222222222222"


def _event(event_id: str = EVENT) -> dict:
    return {
        "id": event_id,
        "tenant_id": TENANT,
        "ocsf_event": {"class_uid": 3002, "time": "2026-11-09T00:00:00Z"},
    }


class _Client:
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.calls: list[tuple] = []

    def execute(self, sql, rows, **kwargs):
        self.calls.append((sql, rows, kwargs))
        if self.fail:
            raise OSError("connection lost")


async def test_success_acknowledges_only_after_insert() -> None:
    client = _Client()
    await DurableLakeSink(client).persist(_event())
    assert len(client.calls) == 1
    assert client.calls[0][1][0]["event_id"] == EVENT


async def test_insert_failure_raises_and_keeps_same_event_identity_for_retry() -> None:
    client = _Client(fail=True)
    sink = DurableLakeSink(client)
    with pytest.raises(LakePersistenceError, match="not acknowledged"):
        await sink.persist(_event())
    client.fail = False
    await sink.persist(_event())
    assert len(client.calls) == 2
    assert client.calls[0][1][0]["event_id"] == client.calls[1][1][0]["event_id"]


async def test_missing_client_and_invalid_event_fail_closed() -> None:
    with pytest.raises(LakePersistenceError, match="unavailable"):
        await DurableLakeSink(None).persist(_event())
    client = _Client()
    with pytest.raises(LakePersistenceError, match="deterministic UUID"):
        await DurableLakeSink(client).persist(_event("invalid"))
    with pytest.raises(LakePersistenceError, match="valid tenant"):
        await DurableLakeSink(client).persist({"id": EVENT, "tenant_id": "invalid", "ocsf_event": {}})
    assert client.calls == []
