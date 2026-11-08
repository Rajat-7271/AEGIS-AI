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
    db.rollback = AsyncMock()
    with patch("app.services.account_email_workflow.verify_email_change_totp", new_callable=AsyncMock), patch(
        "app.services.account_email_workflow.create_pending_email_change",
        new_callable=AsyncMock, return_value=("new@example.com", "a" * 43, "old@example.com"),
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
                current_password="example-password",
                proposed_email="new@example.com", totp_code="123456",
                origin="https://example.com", mailer=MagicMock(),
            )
    db.execute.assert_awaited_once()
    assert db.commit.await_count == 2


@pytest.mark.asyncio
async def test_notice_precedes_verification_and_no_cancel_on_success():
    db = MagicMock()
    db.execute = AsyncMock()
    db.commit = AsyncMock()
    delivery_order = []

    async def notify(**kwargs):
        delivery_order.append(("notice", kwargs["recipient"]))

    async def verify(**kwargs):
        delivery_order.append(("verify", kwargs["recipient"]))

    with patch("app.services.account_email_workflow.verify_email_change_totp", new_callable=AsyncMock) as step_up, patch(
        "app.services.account_email_workflow.create_pending_email_change",
        new_callable=AsyncMock, return_value=("new@example.com", "a" * 43, "old@example.com"),
    ), patch(
        "app.services.account_email_workflow.send_email_change_security_notice",
        side_effect=notify,
    ), patch(
        "app.services.account_email_workflow.send_email_change_verification",
        side_effect=verify,
    ):
        await request_verified_email_change(
            db, tenant_id=uuid.uuid4(), user_id=uuid.uuid4(),
            current_password="example-password",
            proposed_email="new@example.com", totp_code="123456",
            origin="https://example.com", mailer=MagicMock(),
        )
    step_up.assert_awaited_once()
    assert delivery_order == [("notice", "old@example.com"), ("verify", "new@example.com")]
    db.execute.assert_not_awaited()
    db.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_failed_step_up_prevents_request_and_mail():
    from app.services.account_email_step_up import EmailChangeStepUpRejected

    db = MagicMock()
    db.rollback = AsyncMock()
    with patch(
        "app.services.account_email_workflow.verify_email_change_totp",
        new_callable=AsyncMock, side_effect=EmailChangeStepUpRejected("Invalid code"),
    ), patch(
        "app.services.account_email_workflow.create_pending_email_change",
        new_callable=AsyncMock,
    ) as create, patch(
        "app.services.account_email_workflow.send_email_change_verification",
        new_callable=AsyncMock,
    ) as send:
        with pytest.raises(EmailChangeStepUpRejected):
            await request_verified_email_change(
                db, tenant_id=uuid.uuid4(), user_id=uuid.uuid4(),
                current_password="example-password",
                proposed_email="new@example.com", totp_code="000000",
                origin="https://example.com", mailer=MagicMock(),
            )
    create.assert_not_awaited()
    send.assert_not_awaited()


@pytest.mark.asyncio
async def test_password_rejection_rolls_back_consumed_totp():
    from app.services.account_email_request import EmailChangeRequestRejected

    db = MagicMock()
    db.commit = AsyncMock()
    db.rollback = AsyncMock()
    with patch(
        "app.services.account_email_workflow.verify_email_change_totp",
        new_callable=AsyncMock,
    ) as step_up, patch(
        "app.services.account_email_workflow.create_pending_email_change",
        new_callable=AsyncMock,
        side_effect=EmailChangeRequestRejected("rejected"),
    ) as create, patch(
        "app.services.account_email_workflow.send_email_change_verification",
        new_callable=AsyncMock,
    ) as send:
        with pytest.raises(EmailChangeRequestRejected):
            await request_verified_email_change(
                db, tenant_id=uuid.uuid4(), user_id=uuid.uuid4(),
                current_password="wrong",
                proposed_email="new@example.com", totp_code="123456",
                origin="https://example.com", mailer=MagicMock(),
            )
    step_up.assert_awaited_once()
    assert create.await_args.kwargs["commit"] is False
    db.rollback.assert_awaited_once()
    db.commit.assert_not_awaited()
    send.assert_not_awaited()
