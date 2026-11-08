"""TOTP step-up for sensitive account changes.

An ordinary access token proves an earlier login, not recent possession of
the authenticator. A code must be checked and consumed before an email change
can be requested. Passkey-only accounts need a separate WebAuthn step-up flow;
never silently downgrade them to password-only changes.
"""

import uuid

from fastapi import HTTPException
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.endpoints.mfa import _decrypt_secret
from app.services import mfa as totp


class EmailChangeStepUpRejected(ValueError):
    """No step-up proof; fail closed."""


async def verify_email_change_totp(
    db: AsyncSession,
    *,
    user_id: uuid.UUID,
    tenant_id: uuid.UUID,
    code: str,
) -> None:
    """Consume a fresh TOTP step once, including across concurrent requests.

    Lock the MFA row so a code used for one account change cannot be replayed
    in a second concurrent request. Caller owns the transaction: commit only
    with the pending change; roll back if downstream validation fails.
    """
    if not isinstance(code, str) or len(code) != 6 or not code.isascii() or not code.isdigit():
        raise EmailChangeStepUpRejected("Authenticator verification failed")
    result = await db.execute(
        text(
            "SELECT secret_encrypted, confirmed_at, last_used_step "
            "FROM aisoc_user_mfa "
            "WHERE user_id = :u AND tenant_id = :t FOR UPDATE"
        ).bindparams(u=user_id, t=tenant_id)
    )
    row = result.mappings().first()
    if not row or not row["confirmed_at"]:
        raise EmailChangeStepUpRejected("Authenticator verification failed")
    try:
        secret = _decrypt_secret(row["secret_encrypted"])
        step = totp.verify_totp(secret, code, last_used_step=row["last_used_step"])
    except HTTPException:
        raise EmailChangeStepUpRejected("Authenticator verification failed") from None
    if step is None:
        raise EmailChangeStepUpRejected("Authenticator verification failed")
    await db.execute(
        text(
            "UPDATE aisoc_user_mfa SET last_used_step = :step, updated_at = now() "
            "WHERE user_id = :u AND tenant_id = :t"
        ).bindparams(step=step, u=user_id, t=tenant_id)
    )
