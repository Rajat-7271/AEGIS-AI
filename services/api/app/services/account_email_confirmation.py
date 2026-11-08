"""Transactional confirmation of a previously verified email-change request.

This function is intentionally not exposed as an API route until the request,
notification, MFA step-up, and recovery flows have been completed.
"""

from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.account_email_change import AccountEmailChangeRequest
from app.models.tenant import User
from app.services.account_email_verification import (
    email_change_is_confirmable,
    hash_email_verification_token,
)


class EmailChangeRejected(ValueError):
    """Uniform rejection without revealing whether an address is registered."""


async def confirm_pending_email_change(
    db: AsyncSession,
    *,
    tenant_id: object,
    user_id: object,
    token: str,
) -> None:
    """Confirm for the authenticated tenant/user, consuming the token once.

    Call only after the request is authenticated and the tenant RLS context
    is bound. Locking the user first serializes concurrent requests. All
    mutations commit together, and a uniqueness collision rolls back.
    """
    try:
        digest = hash_email_verification_token(token)
    except ValueError as exc:
        raise EmailChangeRejected("Invalid or expired verification") from exc

    user = (
        await db.execute(
            select(User)
            .where(User.id == user_id, User.tenant_id == tenant_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    if user is None or not user.is_active:
        raise EmailChangeRejected("Invalid or expired verification")

    pending = (
        await db.execute(
            select(AccountEmailChangeRequest)
            .where(
                AccountEmailChangeRequest.tenant_id == tenant_id,
                AccountEmailChangeRequest.user_id == user_id,
                AccountEmailChangeRequest.token_hash == digest,
            )
            .with_for_update()
        )
    ).scalar_one_or_none()
    now = datetime.now(UTC)
    if pending is None or not email_change_is_confirmable(
        now=now,
        expires_at=pending.expires_at,
        consumed_at=pending.consumed_at,
        cancelled_at=pending.cancelled_at,
        original_email=pending.previous_email,
        current_email=user.email,
        active=user.is_active,
    ):
        raise EmailChangeRejected("Invalid or expired verification")

    duplicate = (
        await db.execute(
            select(User.id).where(
                func.lower(User.email) == pending.proposed_email.lower(),
                User.id != user.id,
            )
        )
    ).scalar_one_or_none()
    if duplicate is not None:
        raise EmailChangeRejected("Invalid or expired verification")

    user.email = pending.proposed_email
    user.sessions_revoked_at = now
    pending.consumed_at = now
    try:
        await db.commit()
    except IntegrityError as exc:
        await db.rollback()
        raise EmailChangeRejected("Invalid or expired verification") from exc
