"""Tests for revoking pending email changes without altering active identity."""

import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import HTTPException

from app.api.v1.endpoints.auth import cancel_own_pending_email_change


def _setup(*, active=True, missing=False):
    principal = SimpleNamespace(user_id=uuid.uuid4(), tenant_id=uuid.uuid4())
    user = SimpleNamespace(
        id=principal.user_id,
        tenant_id=principal.tenant_id,
        email="current@example.com",
        role="admin",
        is_active=active,
    )
    db = MagicMock()
    db.execute = AsyncMock(
        side_effect=[
            MagicMock(scalar_one_or_none=lambda: None if missing else user),
            MagicMock(),
        ]
    )
    db.commit = AsyncMock()
    return principal, user, db


@pytest.mark.asyncio
async def test_cancel_only_pending_request_preserves_active_account():
    principal, user, db = _setup()
    await cancel_own_pending_email_change(principal, db, principal)
    assert user.email == "current@example.com"
    assert user.role == "admin"
    assert db.execute.await_count == 2
    db.commit.assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.parametrize(("active", "missing"), [(False, False), (True, True)])
async def test_cancel_rejects_missing_or_inactive_principal(active, missing):
    principal, user, db = _setup(active=active, missing=missing)
    with pytest.raises(HTTPException) as error:
        await cancel_own_pending_email_change(principal, db, principal)
    assert error.value.status_code == 404
    db.commit.assert_not_awaited()
    assert user.email == "current@example.com"
