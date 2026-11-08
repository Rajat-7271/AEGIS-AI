"""Unit tests for pending email change creation (no SMTP or live DB)."""

import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.core.security import get_password_hash
from app.services.account_email_request import (
    EmailChangeRequestRejected,
    create_pending_email_change,
)
from app.services.account_email_verification import hash_email_verification_token


def _setup(*, active=True):
    tenant_id, user_id = uuid.uuid4(), uuid.uuid4()
    user = SimpleNamespace(
        id=user_id,
        tenant_id=tenant_id,
        email="original@example.com",
        is_active=active,
        hashed_password=get_password_hash("original-password-123"),
    )
    db = MagicMock()
    db.execute = AsyncMock(return_value=MagicMock(scalar_one_or_none=lambda: user))
    db.commit = AsyncMock()
    db.flush = AsyncMock()
    return tenant_id, user_id, user, db


@pytest.mark.asyncio
async def test_creates_digest_only_and_preserves_active_identity():
    tenant_id, user_id, user, db = _setup()
    recipient, token = await create_pending_email_change(
        db,
        tenant_id=tenant_id,
        user_id=user_id,
        current_password="original-password-123",
        proposed_email="new@EXAMPLE.com",
    )
    assert recipient == "new@example.com"
    assert user.email == "original@example.com"
    db.add.assert_called_once()
    pending = db.add.call_args.args[0]
    assert pending.tenant_id == tenant_id
    assert pending.user_id == user_id
    assert pending.previous_email == user.email
    assert pending.proposed_email == recipient
    assert pending.token_hash == hash_email_verification_token(token)
    assert token != pending.token_hash
    assert 29 * 60 <= (pending.expires_at - pending.created_at).total_seconds() <= 30 * 60
    db.commit.assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("password", "email", "active"),
    [
        ("wrong-password", "new@example.com", True),
        ("original-password-123", "original@example.com", True),
        ("original-password-123", "bad email", True),
        ("original-password-123", "new@example.com", False),
    ],
)
async def test_rejects_unauthorized_or_invalid_without_writing(password, email, active):
    tenant_id, user_id, user, db = _setup(active=active)
    with pytest.raises(EmailChangeRequestRejected):
        await create_pending_email_change(
            db,
            tenant_id=tenant_id,
            user_id=user_id,
            current_password=password,
            proposed_email=email,
        )
    assert user.email == "original@example.com"
    db.add.assert_not_called()
    db.commit.assert_not_awaited()


@pytest.mark.asyncio
async def test_returns_locked_previous_email_for_security_notice():
    tenant_id, user_id, user, db = _setup()
    recipient, token, previous_email = await create_pending_email_change(
        db,
        tenant_id=tenant_id,
        user_id=user_id,
        current_password="original-password-123",
        proposed_email="new@example.com",
        commit=False,
        include_previous_email=True,
    )
    assert previous_email == "original@example.com"
    assert recipient == "new@example.com"
    assert hash_email_verification_token(token)
    db.commit.assert_not_awaited()
