"""Offline contract checks for the hosted Windows -> Postgres path.

No database, network connection or real Windows logs are used.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import uuid
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException

from app.api.v1.endpoints import windows_security as windows

TENANT = uuid.UUID("11111111-1111-4111-8111-111111111111")
CONNECTOR = uuid.UUID("22222222-2222-4222-8222-222222222222")
TOKEN = "test-connector-push-token"
SECRET = "test-hmac-secret"


def payload() -> bytes:
    """Use the actual Windows connector normalization, not a hand-built API event."""
    from pathlib import Path
    import importlib.util
    import sys
    import types

    root = Path(__file__).resolve().parents[3]
    connector_dir = root / "services" / "connectors" / "app" / "connectors"
    original = {name: sys.modules.get(name) for name in
                ("app", "app.connectors", "app.connectors.base", "app.connectors.windows_event")}
    try:
        app = types.ModuleType("app")
        app.__path__ = [str(connector_dir.parent)]
        package = types.ModuleType("app.connectors")
        package.__path__ = [str(connector_dir)]
        sys.modules["app"] = app
        sys.modules["app.connectors"] = package
        for name in ("base", "windows_event"):
            spec = importlib.util.spec_from_file_location(
                "app.connectors." + name, connector_dir / (name + ".py")
            )
            module = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = module
            spec.loader.exec_module(module)
        connector = sys.modules["app.connectors.windows_event"].WindowsEventConnector(
            "https://unused.invalid", "unused"
        )
        stamp = "2026-11-10T12:34:56.0000000Z"
        system = {
            "EventID": 1102, "Channel": "Security", "Computer": "test-windows-host",
            "EventRecordID": 42, "TimeCreated": stamp,
            "Provider": "Microsoft-Windows-Eventlog",
        }
        event = connector.normalize({"System": system, "EventData": {}})
    finally:
        for name, old in original.items():
            if old is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = old
    return json.dumps({
        "connector_id": str(CONNECTOR),
        "connector_type": "windows_event", "source_format": "raw_json",
        "events": [event],
    }).encode()


class FakeResult:
    def __init__(self, value=None, rows=None):
        self.value = value
        self.rows = rows or []

    def scalar_one_or_none(self):
        return self.value

    def __iter__(self):
        return iter(self.rows)


class FakeDB:
    def __init__(self, token=TOKEN, tenant=TENANT, secret=SECRET):
        self.credential = SimpleNamespace(
            token=token, tenant_id=tenant, hmac_secret=secret,
            template_id="connector-push", revoked_at=None,
        )
        self.statements = []
        self.commits = 0

    async def execute(self, statement, params=None):
        self.statements.append((str(statement), params))
        if "FROM tenant_inbox_tokens" in str(statement):
            return FakeResult(self.credential)
        return FakeResult(rows=[])

    async def commit(self):
        self.commits += 1


@pytest.mark.asyncio
async def test_signed_windows_batch_is_persisted_and_acknowledged(monkeypatch):
    db = FakeDB()
    contexts = []
    async def set_context(session, tenant):
        contexts.append(tenant)
    monkeypatch.setattr(windows, "set_rls_context", set_context)
    body = payload()
    signature = "sha256=" + hmac.new(SECRET.encode(), body, hashlib.sha256).hexdigest()
    request = SimpleNamespace(body=AsyncMock(return_value=body))
    response = await windows.ingest_windows(
        request=request, db=db, authorization=f"Bearer {TOKEN}",
        tenant_header=str(TENANT), x_signature=signature,
    )
    assert response == {"accepted": 1, "rejected": 0}
    assert contexts == [TENANT, TENANT]
    inserts = [(sql, params) for sql, params in db.statements if "INSERT INTO windows_security_events" in sql]
    assert len(inserts) == 1
    assert inserts[0][1]["tenant"] == TENANT
    assert inserts[0][1]["code"] == 1102
    assert inserts[0][1]["host"] == "test-windows-host"
    assert db.commits == 1


@pytest.mark.asyncio
async def test_wrong_signature_rejects_without_insert(monkeypatch):
    db = FakeDB()
    monkeypatch.setattr(windows, "set_rls_context", AsyncMock())
    with pytest.raises(HTTPException) as exc:
        await windows.ingest_windows(
            request=SimpleNamespace(body=AsyncMock(return_value=payload())),
            db=db, authorization=f"Bearer {TOKEN}", tenant_header=str(TENANT),
            x_signature="sha256=wrong",
        )
    assert exc.value.status_code == 401
    assert not any("INSERT INTO windows_security_events" in sql for sql, _ in db.statements)
    assert db.commits == 0


@pytest.mark.asyncio
async def test_missing_tenant_header_fails_closed(monkeypatch):
    db = FakeDB()
    monkeypatch.setattr(windows, "set_rls_context", AsyncMock())
    with pytest.raises(HTTPException) as exc:
        await windows.ingest_windows(
            request=SimpleNamespace(body=AsyncMock(return_value=payload())),
            db=db, authorization=f"Bearer {TOKEN}", tenant_header=None,
        )
    assert exc.value.status_code == 400
    assert db.statements == []


@pytest.mark.asyncio
async def test_hosted_event_list_uses_authenticated_tenant(monkeypatch):
    db = FakeDB()
    monkeypatch.setattr(windows, "set_rls_context", AsyncMock())
    user = SimpleNamespace(tenant_id=TENANT)
    response = await windows.list_windows_events(user=user, db=db, limit=100)
    assert response["rows"] == []
    assert response["row_count"] == 0
    assert any(params == {"tenant": TENANT, "limit": 100} for _, params in db.statements)
