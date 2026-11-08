"""Create pending email-change requests without changing the active login.

This is an internal service only. The public API must enforce MFA step-up,
rate limits, trusted delivery origin, old-address notice and recovery before
calling it.
"""

from datetime import UTC, datetime, timedelta

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import verify_password
from app.models.account_email_change import AccountEmailChangeRequest
from app.models.tenant import User
from app.services.account_email_verification import (
    issue_email_verification_token,
    normalize_proposed_email,
)


class EmailChangeRequestRejected(ValueError):
    """Uniform failure; never reveal another account's email address."""


async def create_pending_email_change(
    db: AsyncSession,
    *,
    tenant_id: object,
    user_id: object,
    current_password: str,
    proposed_email: str,
) -> tuple[str, str]:
    """Return (recipient, secret token) after persisting its digest.

    The caller must deliver the secret only to the proposed address.
    Caller must bind tenant RLS and apply MFA, throttling and notifications.
    """
    user = (
        await db.execute(
            select(User)
            .where(User.id == user_id, User.tenant_id == tenant_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    if user is None or not user.is_active or not verify_password(
        current_password, user.hashed_password
    ):
        raise EmailChangeRequestRejected("Email change could not be requested")

    try:
        recipient = normalize_proposed_email(proposed_email, current_email=user.email)
    except ValueError as exc:
        raise EmailChangeRequestRejected("Email change could not be requested") from exc

    now = datetime.now(UTC)
    # A pending request is replaced under the same user row lock. This avoids
    # collisions with the one-pending-request-per-user partial unique index.
    await db.execute(
        update(AccountEmailChangeRequest)
        .where(
            AccountEmailChangeRequest.tenant_id == tenant_id,
            AccountEmailChangeRequest.user_id == user_id,
            AccountEmailChangeRequest.consumed_at.is_(None),
            AccountEmailChangeRequest.cancelled_at.is_(None),
        )
        .values(cancelled_at=now)
    )
    token, digest = issue_email_verification_token()
    db.add(
        AccountEmailChangeRequest(
            tenant_id=tenant_id,
            user_id=user_id,
            previous_email=user.email,
            proposed_email=recipient,
            token_hash=digest,
            created_at=now,
            expires_at=now + timedelta(minutes=30),
        )
    )
    await db.commit()
    return recipient, token
