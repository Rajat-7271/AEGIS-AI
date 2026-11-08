"""Authentication endpoints: login, refresh, logout, user preferences."""

import hashlib
import logging
import re
import uuid
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import AuthUser, DBSession, get_current_user, require_permission
from app.core.config import settings
from app.core.role_grants import wildcard_roles as WILDCARD_ROLES
from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    get_password_hash,
    token_is_revoked,
    verify_password,
)
from app.db.rls import set_rls_context
from app.models.account_email_change import AccountEmailChangeRequest
from app.models.tenant import Tenant, User
from app.models.tenant_admin_invitation import TenantAdminInvitation
from app.services.audit import emit_audit
from app.services.account_email_confirmation import EmailChangeRejected, confirm_pending_email_change
from app.services.account_email_delivery import verification_link
from app.services.account_email_request import EmailChangeRequestRejected
from app.services.account_email_step_up import EmailChangeStepUpRejected
from app.services.account_email_workflow import EmailChangeDeliveryRejected, request_verified_email_change
from app.services.email_approval import MailgunClient
from app.services.login_throttle import client_ip, get_login_throttle
from app.services.waitlist import get_signup_rate_limiter

__all__ = ["router", "get_current_user"]

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])

_INVITE_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")
_TENANT_SLUG_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{1,58}[a-z0-9])?$")
_INITIAL_ADMIN_SENTINEL = "!invite-pending"
_INVITATION_ERROR = "This invitation is invalid, expired, or already used."


async def _apply_invitation_rate_limit(request: Request) -> None:
    source = client_ip(request)
    decision = await get_signup_rate_limiter().acquire(f"admin-invitation:{source}")
    if not decision.allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many invitation attempts. Try again later.",
            headers=decision.to_headers(),
        )


async def _invitation_target(
    db: AsyncSession,
    *,
    token: object,
    tenant_slug: object,
) -> tuple[TenantAdminInvitation, User] | None:
    """Resolve only a live invite and its still-pending, fixed admin user."""
    if not isinstance(token, str) or not _INVITE_TOKEN_RE.fullmatch(token):
        return None
    if not isinstance(tenant_slug, str) or not _TENANT_SLUG_RE.fullmatch(tenant_slug):
        return None

    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    invitation = (
        await db.execute(
            select(TenantAdminInvitation).where(
                # Resolve the supplied tenant slug before reading the bearer
                # credential. This keeps the invitation lookup tenant-scoped
                # even though the caller is not authenticated yet.
                TenantAdminInvitation.tenant_id
                == select(Tenant.id)
                .where(
                    Tenant.slug == tenant_slug,
                    Tenant.is_active.is_(True),
                )
                .scalar_subquery(),
                TenantAdminInvitation.token_hash == token_hash,
                TenantAdminInvitation.expires_at > func.now(),
                TenantAdminInvitation.consumed_at.is_(None),
                TenantAdminInvitation.revoked_at.is_(None),
            )
        )
    ).scalar_one_or_none()
    if invitation is None:
        return None

    tenant = (
        await db.execute(
            select(Tenant).where(
                Tenant.id == invitation.tenant_id,
                Tenant.slug == tenant_slug,
                Tenant.is_active.is_(True),
            )
        )
    ).scalar_one_or_none()
    if tenant is None:
        return None

    user = (
        await db.execute(
            select(User).where(
                User.id == invitation.user_id,
                User.tenant_id == invitation.tenant_id,
                User.role == "tenant_admin",
                User.is_active.is_(False),
                User.is_verified.is_(False),
                User.hashed_password == _INITIAL_ADMIN_SENTINEL,
            )
        )
    ).scalar_one_or_none()
    if user is None:
        return None
    await set_rls_context(db, invitation.tenant_id)
    return invitation, user


@router.post("/invitations/validate", response_model=dict[str, bool])
async def validate_admin_invitation(request: Request, db: DBSession) -> dict[str, bool]:
    """Validate a bearer invite without disclosing the invited account."""
    await _apply_invitation_rate_limit(request)
    try:
        body = await request.json()
    except Exception:  # noqa: BLE001 — malformed body gets the same generic reply
        body = None
    if not isinstance(body, dict):
        return {"valid": False}
    target = await _invitation_target(db, token=body.get("token"), tenant_slug=body.get("tenant"))
    return {"valid": target is not None}


@router.post("/invitations/redeem", response_model=dict[str, bool])
async def redeem_admin_invitation(request: Request, db: DBSession) -> dict[str, bool]:
    """Atomically consume an invite and activate only its bound initial admin."""
    await _apply_invitation_rate_limit(request)
    try:
        body = await request.json()
    except Exception:  # noqa: BLE001 — do not echo malformed request data
        body = None
    if not isinstance(body, dict):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=_INVITATION_ERROR)

    token = body.get("token")
    tenant_slug = body.get("tenant")
    password = body.get("password")
    if not isinstance(password, str) or len(password) < 12 or len(password.encode("utf-8")) > 72:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must be at least 12 characters and no more than 72 UTF-8 bytes.",
        )

    target = await _invitation_target(db, token=token, tenant_slug=tenant_slug)
    if target is None or not isinstance(token, str):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=_INVITATION_ERROR)
    invitation, user = target

    # Claim the invite with a conditional UPDATE. PostgreSQL serializes
    # competing redemptions on this row, so exactly one request can proceed.
    now = datetime.now(UTC)
    claimed = await db.execute(
        update(TenantAdminInvitation)
        .where(
            TenantAdminInvitation.id == invitation.id,
            TenantAdminInvitation.tenant_id == user.tenant_id,
            TenantAdminInvitation.user_id == user.id,
            TenantAdminInvitation.token_hash == hashlib.sha256(token.encode("utf-8")).hexdigest(),
            TenantAdminInvitation.expires_at > func.now(),
            TenantAdminInvitation.consumed_at.is_(None),
            TenantAdminInvitation.revoked_at.is_(None),
        )
        .values(consumed_at=now)
        .returning(TenantAdminInvitation.id)
    )
    if claimed.scalar_one_or_none() is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=_INVITATION_ERROR)

    activated = await db.execute(
        update(User)
        .where(
            User.id == user.id,
            User.tenant_id == invitation.tenant_id,
            User.role == "tenant_admin",
            User.is_active.is_(False),
            User.is_verified.is_(False),
            User.hashed_password == _INITIAL_ADMIN_SENTINEL,
        )
        .values(
            hashed_password=get_password_hash(password),
            is_active=True,
            is_verified=True,
            sessions_revoked_at=now,
            updated_at=now,
        )
        .returning(User.id)
    )
    if activated.scalar_one_or_none() is None:
        # Raising makes get_db roll back both the token claim and user update.
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=_INVITATION_ERROR)
    return {"ok": True}


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int = settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60


class RefreshRequest(BaseModel):
    refresh_token: str


class UserMeResponse(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    email: str
    username: str
    role: str
    is_active: bool
    preferences: dict[str, Any] = {}

    model_config = {"from_attributes": True}


class ProfileNameUpdate(BaseModel):
    username: str


class EmailChangeStartRequest(BaseModel):
    proposed_email: EmailStr
    current_password: str
    totp_code: str


class EmailChangeConfirmRequest(BaseModel):
    token: str


class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str


class PreferencesPatch(BaseModel):
    """Partial update payload for user preferences (merged server-side)."""

    preferences: dict[str, Any]


# The throttle runs *before* the password is verified, and answers the same
# whether the account exists or not. A throttle that engaged only for real
# accounts would reply 429 for those and 401 for the rest, and that difference
# is a user list.
#
# The explanation lives here rather than in the docstring because the
# docstring is published as the operation's `description` in
# `docs/openapi.yaml`, and an API description should say what the endpoint
# does, not what it used to do wrong.
@router.post(
    "/login",
    response_model=TokenResponse,
    responses={
        202: {
            "description": (
                "The password was accepted and a second factor is outstanding. The body carries "
                "`mfa_token` plus either `mfa_required` (complete it at `POST /auth/mfa/verify`) or "
                "`mfa_enrollment_required` (the tenant requires a factor this account has not enrolled; "
                "enrol at `POST /auth/mfa/enroll/begin`). No session is issued."
            ),
            "content": {"application/json": {"example": {"mfa_required": True, "mfa_token": "eyJ…", "methods": ["totp", "recovery_code"]}}},
        }
    },
)
async def login(request: LoginRequest, http_request: Request, db: DBSession) -> TokenResponse | JSONResponse:
    """Authenticate with email/password, return JWT tokens."""
    throttle = get_login_throttle()
    source = client_ip(http_request)
    decision = await throttle.check(email=request.email, source_ip=source)
    if not decision.allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=decision.detail,
            headers={"Retry-After": str(decision.retry_after_seconds)},
        )

    result = await db.execute(select(User).where(User.email == request.email, User.is_active.is_(True)))
    user = result.scalar_one_or_none()

    if user is None or not verify_password(request.password, user.hashed_password):
        locked = await throttle.record_failure(email=request.email, source_ip=source)
        if locked.locked_out:
            logger.warning(
                "login lockout: %s principal locked after %d failures (ip=%s)",
                locked.scope,
                locked.failures,
                str(source).replace("\r", "").replace("\n", " ")[:64],
            )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Break-glass policy: once SSO is enabled, an operator may close the
    # password door for everyone except the wildcard roles, so local
    # accounts survive as the path that works when the IdP is down -- and
    # only as that path. Answered after password verification so it leaks
    # nothing about which addresses exist, and throttled above like every
    # other attempt here.
    sso_enabled = (settings_dict().get("SSO_ENABLED") or "false").strip().lower() in {"1", "true", "yes", "on"}
    local_admin_only = (settings_dict().get("SSO_LOCAL_ADMIN_ONLY") or "false").strip().lower() in {"1", "true", "yes", "on"}
    if sso_enabled and local_admin_only and user.role not in WILDCARD_ROLES():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Password sign-in is disabled for this account. Use single sign-on.",
        )

    await throttle.record_success(email=request.email, source_ip=source)

    # Fix pass 4.2. The password is one factor, and for an enrolled user or
    # an enforcing tenant it is no longer the whole answer. Answered as 202
    # rather than by widening the 200 body: `access_token` and
    # `refresh_token` are required fields of `TokenResponse`, and making
    # either optional is a break for every generated client.
    challenge = await mfa_challenge_for(db, user_id=user.id, tenant_id=user.tenant_id, role=user.role)
    if challenge is not None:
        return JSONResponse(status_code=status.HTTP_202_ACCEPTED, content=challenge)

    # Update last login
    await db.execute(update(User).where(User.id == user.id).values(last_login=datetime.now(UTC)))

    token_data = {
        "sub": str(user.id),
        "tenant_id": str(user.tenant_id),
        "role": user.role,
        "email": user.email,
    }
    access_token = create_access_token(token_data)
    refresh_token = create_refresh_token(token_data)

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
    )


async def mfa_challenge_for(
    db: Any,
    *,
    user_id: uuid.UUID,
    tenant_id: uuid.UUID,
    role: str | None = None,
) -> dict[str, Any] | None:
    """What this account still owes before a session is issued, or `None`.

    Two cases and they are not the same thing. An enrolled user owes a
    proof. A user the policy covers who has never enrolled owes an
    enrolment — refusing them instead would lock out every unenrolled
    user the moment an administrator turns the policy on, which is the
    whole tenant at once.

    `role` is how depth 8.1's per-role enforcement arrives. It defaults to
    `None`, which `mfa_required_for` answers from the tenant-wide switch
    alone, so a caller that has not been taught about roles enforces
    exactly what it enforced before rather than silently enforcing less.

    A failure to read either table is **not** treated as "no MFA". That
    would fail open at the one place in the product where open is worst.
    """
    from app.api.v1.endpoints.mfa import has_confirmed_factor, has_webauthn_factor, mfa_required_for, mint_challenge

    if await has_confirmed_factor(db, user_id, tenant_id):
        # Only the methods this account can actually use. Offering
        # `webauthn` to somebody with no authenticator sends them to a
        # browser prompt that cannot succeed, and offering `totp` to
        # somebody whose only factor is a security key asks for a code
        # from an app they never set up.
        methods = ["totp", "recovery_code"] if await _has_totp(db, user_id) else []
        if await has_webauthn_factor(db, user_id, tenant_id):
            methods.append("webauthn")
        return {
            "mfa_required": True,
            "mfa_token": mint_challenge(user_id=user_id, tenant_id=tenant_id, purpose="verify"),
            "methods": methods,
        }
    if await mfa_required_for(db, tenant_id, role):
        return {
            "mfa_enrollment_required": True,
            "mfa_token": mint_challenge(user_id=user_id, tenant_id=tenant_id, purpose="enroll"),
        }
    return None


async def _has_totp(db: Any, user_id: uuid.UUID) -> bool:
    from app.api.v1.endpoints.mfa import enrolment_row

    row = await enrolment_row(db, user_id)
    return bool(row and row["confirmed_at"])


def settings_dict() -> dict[str, str]:
    """The SSO-related environment, read live so an operator can flip the
    flag without a redeploy. Anything unset reads as its safe default."""
    import os

    return {k: (os.getenv(k) or "") for k in ("SSO_ENABLED", "SSO_LOCAL_ADMIN_ONLY", "SSO_LOGIN_LABEL", "SSO_PROVIDER")}


@router.get("/sso/status")
async def sso_status() -> dict[str, Any]:
    """What the login screen asks before it offers SSO. Public: it reveals
    only that SSO is offered, under what label, and whether password sign-in
    remains open -- never issuers, client ids, endpoints or secrets."""
    d = settings_dict()
    enabled = d["SSO_ENABLED"].strip().lower() in {"1", "true", "yes", "on"}
    local_admin_only = d["SSO_LOCAL_ADMIN_ONLY"].strip().lower() in {"1", "true", "yes", "on"}
    return {
        "sso_enabled": enabled,
        "provider": (d["SSO_PROVIDER"] or "oidc").strip().lower(),
        "login_label": (d["SSO_LOGIN_LABEL"] or "Continue with SSO").strip()[:80],
        "local_login_enabled": (not enabled) or (not local_admin_only),
    }


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(request: RefreshRequest, db: DBSession) -> TokenResponse:
    """Refresh access token using a valid refresh token."""
    try:
        payload = decode_token(request.refresh_token)
        if payload.get("type") != "refresh":
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token type")
        user_id = payload.get("sub")
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token") from e

    result = await db.execute(select(User).where(User.id == uuid.UUID(user_id), User.is_active.is_(True)))
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")

    # A refresh token outlives an access token by days, so without this a
    # deprovisioned principal who is later re-activated could mint a fresh
    # session from a token issued before the revocation.
    if token_is_revoked(payload.get("iat"), user.sessions_revoked_at):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session revoked")

    token_data = {
        "sub": str(user.id),
        "tenant_id": str(user.tenant_id),
        "role": user.role,
        "email": user.email,
    }
    return TokenResponse(
        access_token=create_access_token(token_data),
        refresh_token=create_refresh_token(token_data),
    )


@router.get("/me", response_model=UserMeResponse)
async def get_me(current_user: AuthUser, db: DBSession) -> UserMeResponse:
    """Get current authenticated user info."""
    result = await db.execute(select(User).where(User.id == current_user.user_id))
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return UserMeResponse.model_validate(user)


@router.patch("/me/preferences", response_model=UserMeResponse)
async def patch_me_preferences(
    body: PreferencesPatch,
    current_user: AuthUser,
    db: DBSession,
) -> UserMeResponse:
    """Merge user preferences (e.g. theme) into the stored JSONB column.

    Only the keys supplied in the request body are updated; all other
    existing keys are preserved.  This lets the frontend evolve independent
    preference namespaces without overwriting each other.
    """
    result = await db.execute(select(User).where(User.id == current_user.user_id))
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    merged = {**(user.preferences or {}), **body.preferences}
    await db.execute(update(User).where(User.id == current_user.user_id).values(preferences=merged))
    await db.commit()

    # Re-fetch to return fresh state
    result = await db.execute(select(User).where(User.id == current_user.user_id))
    user = result.scalar_one_or_none()
    return UserMeResponse.model_validate(user)


@router.patch("/me/name", response_model=UserMeResponse)
async def change_own_display_name(
    body: ProfileNameUpdate,
    current_user: AuthUser,
    db: DBSession,
    _authorized: Annotated[Any, Depends(require_permission("settings:write"))],
) -> UserMeResponse:
    """Update only the authenticated user's display name, never their role."""
    name = body.username.strip()
    if (
        not 1 <= len(name) <= 100
        or any(ord(char) < 32 or ord(char) == 127 for char in name)
    ):
        raise HTTPException(status_code=400, detail="Display name must be 1-100 printable characters")
    user = (
        await db.execute(
            select(User)
            .where(User.id == current_user.user_id, User.tenant_id == current_user.tenant_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    if user is None or not user.is_active:
        raise HTTPException(status_code=404, detail="User not found")
    user.username = name
    await db.commit()
    return UserMeResponse.model_validate(user)


async def _limit_email_change_attempt(request: Request, user_id: uuid.UUID) -> None:
    """Bound sensitive attempts by both caller source and account identity."""
    limiter = get_signup_rate_limiter()
    for key in (
        f"account-email-change:source:{client_ip(request)}",
        f"account-email-change:user:{user_id}",
    ):
        decision = await limiter.acquire(key)
        if not decision.allowed:
            raise HTTPException(
                status_code=429,
                detail="Too many account-change attempts. Try again later.",
                headers=decision.to_headers(),
            )


@router.post("/me/email-change/request", status_code=status.HTTP_202_ACCEPTED)
async def request_own_email_change(
    body: EmailChangeStartRequest,
    request: Request,
    current_user: AuthUser,
    db: DBSession,
    _authorized: Annotated[Any, Depends(require_permission("settings:write"))],
) -> dict[str, str]:
    """Send verification to the proposed address only after TOTP step-up."""
    await _limit_email_change_attempt(request, current_user.user_id)
    origin = (settings.CONSOLE_PUBLIC_BASE_URL or "").strip()
    # Never derive verification hosts from attacker-controlled Host headers.
    try:
        verification_link(origin=origin, token="a" * 43)
    except ValueError as exc:
        raise HTTPException(status_code=503, detail="Email verification is not configured") from exc
    mailer = MailgunClient()
    try:
        await request_verified_email_change(
            db,
            tenant_id=current_user.tenant_id,
            user_id=current_user.user_id,
            current_password=body.current_password,
            proposed_email=str(body.proposed_email),
            totp_code=body.totp_code,
            origin=origin,
            mailer=mailer,
        )
    except (EmailChangeRequestRejected, EmailChangeStepUpRejected) as exc:
        raise HTTPException(status_code=403, detail="Email change could not be requested") from exc
    except EmailChangeDeliveryRejected as exc:
        raise HTTPException(status_code=503, detail="Email verification could not be delivered") from exc
    finally:
        await mailer.aclose()
    await emit_audit(
        db=db,
        tenant_id=current_user.tenant_id,
        actor_id=current_user.user_id,
        action="auth.email_change.requested",
        resource="user",
        resource_id=str(current_user.user_id),
        changes={"verification_required": True},
        request=request,
    )
    await db.commit()
    return {"message": "Check your new email address for a verification link."}


@router.post("/me/email-change/confirm", status_code=status.HTTP_204_NO_CONTENT)
async def confirm_own_email_change(
    body: EmailChangeConfirmRequest,
    request: Request,
    current_user: AuthUser,
    db: DBSession,
    _authorized: Annotated[Any, Depends(require_permission("settings:write"))],
) -> None:
    """Consume a verification token only for its authenticated owner."""
    await _limit_email_change_attempt(request, current_user.user_id)
    try:
        await confirm_pending_email_change(
            db,
            tenant_id=current_user.tenant_id,
            user_id=current_user.user_id,
            token=body.token,
        )
    except EmailChangeRejected as exc:
        raise HTTPException(status_code=400, detail="Invalid or expired verification") from exc
    await emit_audit(
        db=db,
        tenant_id=current_user.tenant_id,
        actor_id=current_user.user_id,
        action="auth.email_change.confirmed",
        resource="user",
        resource_id=str(current_user.user_id),
        changes={"sessions_revoked": True},
        request=request,
    )
    await db.commit()


@router.delete("/me/pending-email-change", status_code=status.HTTP_204_NO_CONTENT)
async def cancel_own_pending_email_change(
    current_user: AuthUser,
    db: DBSession,
    _authorized: Annotated[Any, Depends(require_permission("settings:write"))],
) -> None:
    """Revoke any unconfirmed email-change link for the current account.

    No email-change token or user ID is accepted from the caller. This
    operation is safe to repeat and never changes the active login address.
    """
    user = (
        await db.execute(
            select(User)
            .where(User.id == current_user.user_id, User.tenant_id == current_user.tenant_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    if user is None or not user.is_active:
        raise HTTPException(status_code=404, detail="User not found")
    await db.execute(
        update(AccountEmailChangeRequest)
        .where(
            AccountEmailChangeRequest.tenant_id == current_user.tenant_id,
            AccountEmailChangeRequest.user_id == current_user.user_id,
            AccountEmailChangeRequest.consumed_at.is_(None),
            AccountEmailChangeRequest.cancelled_at.is_(None),
        )
        .values(cancelled_at=datetime.now(UTC))
    )
    await db.commit()


@router.post("/me/change-password", status_code=status.HTTP_204_NO_CONTENT)
async def change_own_password(
    body: PasswordChangeRequest,
    current_user: AuthUser,
    db: DBSession,
    _authorized: Annotated[Any, Depends(require_permission("settings:write"))],
) -> None:
    """Rotate the authenticated principal's password without changing identity or role.

    Existing sessions are revoked, including this session. The caller must sign in
    again with the new password. Never accept a user ID from the request body.
    """
    if len(body.new_password) < 12 or len(body.new_password.encode("utf-8")) > 72:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New password must be at least 12 characters and at most 72 UTF-8 bytes.",
        )
    user = (
        await db.execute(
            select(User).where(User.id == current_user.user_id, User.tenant_id == current_user.tenant_id).with_for_update()
        )
    ).scalar_one_or_none()
    if user is None or not user.is_active:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    if not verify_password(body.current_password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Current password is incorrect")
    if verify_password(body.new_password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Choose a different password")

    user.hashed_password = get_password_hash(body.new_password)
    user.sessions_revoked_at = datetime.now(UTC)
    await db.commit()
