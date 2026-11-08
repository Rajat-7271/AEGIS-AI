"""Authenticated email-change route tests with external effects mocked."""

import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException

from app.api.v1.endpoints.auth import (
    EmailChangeConfirmRequest,
    EmailChangeStartRequest,
    confirm_own_email_change,
    request_own_email_change,
)


def _principal():
    return SimpleNamespace(user_id=uuid.uuid4(), tenant_id=uuid.uuid4())


@pytest.mark.asyncio
async def test_confirmation_scopes_token_to_authenticated_user():
    principal = _principal()
    db = MagicMock()
    with patch(
        "app.api.v1.endpoints.auth._limit_email_change_attempt",
        new_callable=AsyncMock,
    ), patch(
        "app.api.v1.endpoints.auth.confirm_pending_email_change",
        new_callable=AsyncMock,
    ) as confirm:
        await confirm_own_email_change(
            EmailChangeConfirmRequest(token="opaque"),
            MagicMock(),
            principal,
            db,
            principal,
        )
    confirm.assert_awaited_once_with(
        db, tenant_id=principal.tenant_id,
        user_id=principal.user_id, token="opaque",
    )


@pytest.mark.asyncio
async def test_request_fails_closed_without_https_origin():
    principal = _principal()
    with patch(
        "app.api.v1.endpoints.auth._limit_email_change_attempt",
        new_callable=AsyncMock,
    ), patch(
        "app.api.v1.endpoints.auth.settings.CONSOLE_PUBLIC_BASE_URL",
        "http://localhost:3000",
    ):
        with pytest.raises(HTTPException) as error:
            await request_own_email_change(
                EmailChangeStartRequest(
                    proposed_email="new@example.com",
                    current_password="example-password",
                    totp_code="123456",
                ),
                MagicMock(),
                principal,
                MagicMock(),
                principal,
            )
    assert error.value.status_code == 503
