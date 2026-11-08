"""Account email delivery orchestration tests."""

from unittest.mock import AsyncMock, MagicMock, patch
import uuid
import pytest

from app.services.account_email_workflow import (
    EmailChangeDeliveryRejected, request_verified_email_change,
)


@pytest.mark.asyncio
async def test_failed_delivery_cancels_pending_request():
    db = MagicMock()
    db.execute = AsyncMock()
    db.commit = AsyncMock()
    with patch("app.services.account_email_workflow.verify_email_change_totp", new_callable=AsyncMock), patch(
        "app.services.account_email_workflow.create_pending_email_change",
        new_callable=AsyncMock, return_value=("new@example.com", "a" * 43),
    ), patch(
        "app.services.account_email_workflow.send_email_change_security_notice",
        new_callable=AsyncMock,
    ), patch(
        "app.services.account_email_workflow.send_email_change_verification",
        new_callable=AsyncMock, side_effect=RuntimeError("mail unavailable"),
    ):
        with pytest.raises(EmailChangeDeliveryRejected):
            await request_verified_email_change(
                db, tenant_id=uuid.uuid4(), user_id=uuid.uuid4(),
                current_email="old@example.com", current_password="example-password",
                proposed_email="new@example.com", totp_code="123456",
                origin="https://example.com", mailer=MagicMock(),
            )
    db.execute.assert_awaited_once()
    db.commit.assert_awaited_once()
