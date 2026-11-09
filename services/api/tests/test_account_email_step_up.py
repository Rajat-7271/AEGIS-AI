"""Email-change TOTP step-up rejects replay and missing factors."""

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from app.services.account_email_step_up import (
    EmailChangeStepUpRejected,
    verify_email_change_totp,
)


def _db(*, enrolled=True):
    db = MagicMock()
    row = (
        {"secret_encrypted": "ciphertext", "confirmed_at": object(), "last_used_step": 10}
        if enrolled
        else None
    )
    first = MagicMock()
    first.mappings.return_value.first.return_value = row
    db.execute = AsyncMock(side_effect=[first, MagicMock()])
    return db


@pytest.mark.asyncio
async def test_consumes_totp_step_without_committing():
    db = _db()
    with patch("app.services.account_email_step_up._decrypt_secret", return_value="secret"), patch(
        "app.services.account_email_step_up.totp.verify_totp", return_value=11
    ) as verify:
        await verify_email_change_totp(
            db, user_id=uuid.uuid4(), tenant_id=uuid.uuid4(), code="123456"
        )
    assert db.execute.await_count == 2
    assert "FOR UPDATE" in str(db.execute.await_args_list[0].args[0])
    assert "last_used_step" in str(db.execute.await_args_list[1].args[0])
    verify.assert_called_once_with("secret", "123456", last_used_step=10)


@pytest.mark.asyncio
@pytest.mark.parametrize("code", ["", "123", "1234567", "abcdef", "１２３４５６"])
async def test_bad_code_never_touches_database(code):
    db = _db()
    with pytest.raises(EmailChangeStepUpRejected):
        await verify_email_change_totp(
            db, user_id=uuid.uuid4(), tenant_id=uuid.uuid4(), code=code
        )
    db.execute.assert_not_awaited()


@pytest.mark.asyncio
async def test_no_enrollment_fails_closed():
    db = _db(enrolled=False)
    with pytest.raises(EmailChangeStepUpRejected):
        await verify_email_change_totp(
            db, user_id=uuid.uuid4(), tenant_id=uuid.uuid4(), code="123456"
        )
    assert db.execute.await_count == 1


@pytest.mark.asyncio
async def test_replayed_code_fails_without_update():
    db = _db()
    with patch("app.services.account_email_step_up._decrypt_secret", return_value="secret"), patch(
        "app.services.account_email_step_up.totp.verify_totp", return_value=None
    ):
        with pytest.raises(EmailChangeStepUpRejected):
            await verify_email_change_totp(
                db, user_id=uuid.uuid4(), tenant_id=uuid.uuid4(), code="123456"
            )
    assert db.execute.await_count == 1
