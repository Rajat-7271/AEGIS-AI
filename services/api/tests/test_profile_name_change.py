"""Regression tests for self-service display-name changes."""

import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from app.api.v1.endpoints.auth import ProfileNameUpdate, change_own_display_name
from fastapi import HTTPException


def _setup():
    principal = SimpleNamespace(user_id=uuid.uuid4(), tenant_id=uuid.uuid4())
    user = SimpleNamespace(
        id=principal.user_id,
        tenant_id=principal.tenant_id,
        username="SOC analyst",
        email="old@example.com",
        role="admin",
        is_active=True,
        preferences={},
    )
    db = MagicMock()
    db.execute = AsyncMock(return_value=MagicMock(scalar_one_or_none=lambda: user))
    db.commit = AsyncMock()
    return principal, user, db


@pytest.mark.asyncio
async def test_name_change_preserves_login_and_permissions():
    principal, user, db = _setup()
    result = await change_own_display_name(
        ProfileNameUpdate(username=" Rajat "),
        principal,
        db,
        principal,
    )
    assert result.username == "Rajat"
    assert user.email == "old@example.com"
    assert user.role == "admin"
    db.commit.assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.parametrize("name", ["", "   ", "x" * 101, "bad\nname"])
async def test_invalid_name_does_not_write(name):
    principal, user, db = _setup()
    with pytest.raises(HTTPException) as error:
        await change_own_display_name(ProfileNameUpdate(username=name), principal, db, principal)
    assert error.value.status_code == 400
    assert user.username == "SOC analyst"
    db.commit.assert_not_awaited()
