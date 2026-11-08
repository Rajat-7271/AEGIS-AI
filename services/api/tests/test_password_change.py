"""Focused regression tests for authenticated self-service password rotation."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import HTTPException

from app.api.v1.endpoints.auth import PasswordChangeRequest, change_own_password
from app.core.security import get_password_hash, verify_password


OLD_PASSWORD = "correct-old-password-123"
NEW_PASSWORD = "different-new-password-456"


def _setup(*, active: bool = True, missing: bool = False):
    principal = SimpleNamespace(user_id=uuid.uuid4(), tenant_id=uuid.uuid4(), role="admin")
    user = SimpleNamespace(
        id=principal.user_id,
        tenant_id=principal.tenant_id,
        role="admin",
        email="operator@example.test",
        is_active=active,
        hashed_password=get_password_hash(OLD_PASSWORD),
        sessions_revoked_at=None,
    )
    db = MagicMock()
    result = MagicMock()
    result.scalar_one_or_none.return_value = None if missing else user
    db.execute = AsyncMock(return_value=result)
    db.commit = AsyncMock()
    return principal, user, db


async def _change(principal, db, current=OLD_PASSWORD, new=NEW_PASSWORD):
    return await change_own_password(
        body=PasswordChangeRequest(current_password=current, new_password=new),
        current_user=principal,
        db=db,
        _authorized=principal,
    )


@pytest.mark.asyncio
async def test_password_rotation_updates_only_credentials_and_revokes_sessions():
    principal, user, db = _setup()
    original = (user.id, user.tenant_id, user.role, user.email)
    old_hash = user.hashed_password
    before = datetime.now(UTC)

    assert await _change(principal, db) is None

    assert user.hashed_password != old_hash
    assert verify_password(NEW_PASSWORD, user.hashed_password)
    assert not verify_password(OLD_PASSWORD, user.hashed_password)
    assert (user.id, user.tenant_id, user.role, user.email) == original
    assert before <= user.sessions_revoked_at <= datetime.now(UTC)
    db.commit.assert_awaited_once()
    assert db.execute.await_count == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("current", "new", "expected"),
    [
        ("wrong-current-password", NEW_PASSWORD, 403),
        (OLD_PASSWORD, OLD_PASSWORD, 400),
        (OLD_PASSWORD, "too-short", 400),
        (OLD_PASSWORD, "é" * 40, 400),
    ],
)
async def test_invalid_password_change_never_commits(current, new, expected):
    principal, user, db = _setup()
    old_hash = user.hashed_password

    with pytest.raises(HTTPException) as exc:
        await _change(principal, db, current, new)

    assert exc.value.status_code == expected
    assert user.hashed_password == old_hash
    assert user.sessions_revoked_at is None
    db.commit.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize(("active", "missing"), [(False, False), (True, True)])
async def test_missing_or_inactive_account_is_rejected(active, missing):
    principal, user, db = _setup(active=active, missing=missing)
    old_hash = user.hashed_password

    with pytest.raises(HTTPException) as exc:
        await _change(principal, db)

    assert exc.value.status_code == 404
    assert user.hashed_password == old_hash
    db.commit.assert_not_awaited()
