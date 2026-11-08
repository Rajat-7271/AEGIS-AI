"""Focused transaction tests for verified email confirmation."""

import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from app.services.account_email_confirmation import (
    EmailChangeRejected,
    confirm_pending_email_change,
)
from app.services.account_email_verification import issue_email_verification_token


def _fixture(*, expired=False, consumed=False, duplicate=False):
    tenant_id, user_id = uuid.uuid4(), uuid.uuid4()
    token, digest = issue_email_verification_token()
    user = SimpleNamespace(
        id=user_id,
        tenant_id=tenant_id,
        email="old@example.com",
        is_active=True,
        sessions_revoked_at=None,
    )
    now = datetime.now(UTC)
    pending = SimpleNamespace(
        tenant_id=tenant_id,
        user_id=user_id,
        token_hash=digest,
        previous_email=user.email,
        proposed_email="new@example.com",
        expires_at=now + timedelta(minutes=-1 if expired else 30),
        consumed_at=now if consumed else None,
        cancelled_at=None,
    )
    db = MagicMock()
    db.execute = AsyncMock()
    db.commit = AsyncMock()
    db.rollback = AsyncMock()
    rows = [user, pending, uuid.uuid4() if duplicate else None, None]
    db.execute.side_effect = [
        MagicMock(scalar_one_or_none=MagicMock(return_value=value))
        for value in rows
    ]
    return db, user, pending, tenant_id, user_id, token


@pytest.mark.asyncio
async def test_confirmation_changes_login_and_revokes_sessions_atomically():
    db, user, pending, tenant_id, user_id, token = _fixture()
    await confirm_pending_email_change(
        db, tenant_id=tenant_id, user_id=user_id, token=token
    )
    assert user.email == "new@example.com"
    assert user.sessions_revoked_at is not None
    assert pending.consumed_at == user.sessions_revoked_at
    db.commit.assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.parametrize("condition", ["expired", "consumed", "duplicate", "invalid"])
async def test_rejected_confirmation_does_not_commit(condition):
    db, user, pending, tenant_id, user_id, token = _fixture(
        expired=condition == "expired",
        consumed=condition == "consumed",
        duplicate=condition == "duplicate",
    )
    if condition == "invalid":
        token = "invalid"
    with pytest.raises(EmailChangeRejected):
        await confirm_pending_email_change(
            db, tenant_id=tenant_id, user_id=user_id, token=token
        )
    assert user.email == "old@example.com"
    assert user.sessions_revoked_at is None
    db.commit.assert_not_awaited()
