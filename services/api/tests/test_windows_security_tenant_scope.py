"""Regression checks for tenant scoping of Windows Security event reads.

These are unit tests, not a live Postgres RLS or cross-tenant integration test.
"""
import asyncio
import uuid
from types import SimpleNamespace
from unittest.mock import patch

from app.api.v1.endpoints.windows_security import list_windows_events


class RecordingSession:
    def __init__(self):
        self.calls = []

    async def execute(self, statement, parameters):
        self.calls.append((str(statement), parameters))
        return []


def test_windows_events_query_is_scoped_to_authenticated_tenant():
    tenant_a = uuid.uuid4()
    tenant_b = uuid.uuid4()
    assert tenant_a != tenant_b

    async def run_for(tenant_id):
        session = RecordingSession()
        user = SimpleNamespace(tenant_id=tenant_id)
        with patch(
            "app.api.v1.endpoints.windows_security.set_rls_context"
        ) as set_context:
            set_context.return_value = asyncio.sleep(0)
            result = await list_windows_events(user=user, db=session, limit=25)
            set_context.assert_called_once_with(session, tenant_id)
        assert result["rows"] == []
        assert len(session.calls) == 1
        statement, params = session.calls[0]
        assert "WHERE tenant_id = :tenant" in statement
        assert params == {"tenant": tenant_id, "limit": 25}
        return params

    first = asyncio.run(run_for(tenant_a))
    second = asyncio.run(run_for(tenant_b))
    assert first["tenant"] != second["tenant"]
