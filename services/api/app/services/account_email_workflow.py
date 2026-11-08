"""Orchestrate step-up, persistence, delivery and failure cancellation.

Internal only until a rate-limited, audited API and recovery UI exist.
Do not log the token, verification URL, or mail-provider exception.
"""

from datetime import UTC, datetime

from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.account_email_change import AccountEmailChangeRequest
from app.services.account_email_delivery import (
    send_email_change_security_notice,
    send_email_change_verification,
)
from app.services.account_email_request import create_pending_email_change
from app.services.account_email_step_up import verify_email_change_totp
from app.services.email_approval import MailgunClient


class EmailChangeDeliveryRejected(ValueError):
    """No usable verification link was issued."""


async def request_verified_email_change(
    db: AsyncSession,
    *,
    tenant_id: object,
    user_id: object,
    current_email: str,
    current_password: str,
    proposed_email: str,
    totp_code: str,
    origin: str,
    mailer: MailgunClient,
) -> None:
    """Request an email change after consuming a fresh authenticator code.

    The step-up and pending request are committed in the same transaction.
    If either delivery fails, cancel the pending request and fail closed.
    """
    await verify_email_change_totp(
        db, user_id=user_id, tenant_id=tenant_id, code=totp_code
    )
    recipient, token = await create_pending_email_change(
        db,
        tenant_id=tenant_id,
        user_id=user_id,
        current_password=current_password,
        proposed_email=proposed_email,
    )
    try:
        await send_email_change_security_notice(
            recipient=current_email,
            proposed_email=recipient,
            mailer=mailer,
        )
        await send_email_change_verification(
            recipient=recipient,
            token=token,
            origin=origin,
            mailer=mailer,
        )
    except Exception:
        # Never leave a valid link behind if the notification chain fails.
        await db.execute(
            update(AccountEmailChangeRequest)
            .where(
                AccountEmailChangeRequest.tenant_id == tenant_id,
                AccountEmailChangeRequest.user_id == user_id,
                AccountEmailChangeRequest.token_hash.isnot(None),
                AccountEmailChangeRequest.consumed_at.is_(None),
                AccountEmailChangeRequest.cancelled_at.is_(None),
            )
            .values(cancelled_at=datetime.now(UTC))
        )
        await db.commit()
        raise EmailChangeDeliveryRejected("Could not send verification email") from None
