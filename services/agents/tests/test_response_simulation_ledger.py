"""Idempotent response-simulation writes in the existing event ledger."""

from __future__ import annotations

import uuid
from contextlib import asynccontextmanager

import pytest
from app.investigator import ledger

pytestmark = pytest.mark.asyncio


class _Connection:
    def __init__(self, *, tenant_id: uuid.UUID, run_id: uuid.UUID, alert_id: str):
        self.tenant_id = tenant_id
        self.run_id = run_id
        self.alert_id = alert_id
        self.events: list[dict] = []

    def transaction(self):
        @asynccontextmanager
        async def _transaction():
            yield

        return _transaction()

    async def fetchrow(self, sql: str, *args):
        if "FROM investigation_runs" in sql:
            return {"id": self.run_id} if args == (self.run_id, self.tenant_id, self.alert_id) else None
        if "FROM investigation_events" in sql:
            return next(
                (
                    {"payload": event["payload"]}
                    for event in self.events
                    if event["run_id"] == args[0] and event["tenant_id"] == args[1] and event["payload"].get("idempotency_key") == args[2]
                ),
                None,
            )
        raise AssertionError(f"unexpected fetchrow query: {sql}")

    async def fetchval(self, sql: str, *args):
        if "MAX(seq)" in sql:
            return max((event["seq"] for event in self.events), default=0) + 1
        if "INSERT INTO investigation_events" in sql:
            import json

            self.events.append(
                {
                    "run_id": args[1],
                    "tenant_id": args[2],
                    "seq": args[3],
                    "payload": json.loads(args[5]),
                }
            )
            return args[0]
        raise AssertionError(f"unexpected fetchval query: {sql}")


class _Pool:
    def __init__(self, conn: _Connection):
        self.conn = conn

    @asynccontextmanager
    async def acquire(self):
        yield self.conn


async def test_response_result_is_tenant_bound_and_idempotent(monkeypatch):
    tenant_id = uuid.uuid4()
    run_id = uuid.uuid4()
    alert_id = str(uuid.uuid4())
    conn = _Connection(tenant_id=tenant_id, run_id=run_id, alert_id=alert_id)
    conn.events.append({"run_id": run_id, "tenant_id": tenant_id, "seq": 1, "payload": {"kind": "triage_verdict"}})
    monkeypatch.setattr(ledger, "get_pool", lambda: _async_value(_Pool(conn)))
    monkeypatch.setattr(ledger, "_set_rls_context", _async_none)

    payload = {"proposal_status": "proposed", "status": "simulated", "simulated": True, "executed": False}
    first = await ledger.record_response_simulation(
        run_id=run_id,
        tenant_id=tenant_id,
        alert_id=alert_id,
        idempotency_key="run:isolate_host:host",
        payload=payload,
    )
    second = await ledger.record_response_simulation(
        run_id=run_id,
        tenant_id=tenant_id,
        alert_id=alert_id,
        idempotency_key="run:isolate_host:host",
        payload={"status": "failed", "simulated": False, "executed": False},
    )

    assert first == {**payload, "idempotency_key": "run:isolate_host:host"}
    assert second == first
    assert len(conn.events) == 2
    assert conn.events[1]["tenant_id"] == tenant_id
    assert conn.events[1]["seq"] == 2


async def test_result_is_not_written_for_a_run_with_different_tenant_or_alert(monkeypatch):
    tenant_id = uuid.uuid4()
    run_id = uuid.uuid4()
    conn = _Connection(tenant_id=tenant_id, run_id=run_id, alert_id=str(uuid.uuid4()))
    monkeypatch.setattr(ledger, "get_pool", lambda: _async_value(_Pool(conn)))
    monkeypatch.setattr(ledger, "_set_rls_context", _async_none)

    result = await ledger.record_response_simulation(
        run_id=run_id,
        tenant_id=uuid.uuid4(),
        alert_id=str(uuid.uuid4()),
        idempotency_key="wrong-owner",
        payload={"status": "simulated", "simulated": True, "executed": False},
    )
    assert result is None
    assert conn.events == []


async def _async_value(value):
    return value


async def _async_none(*_args, **_kwargs):
    return None
