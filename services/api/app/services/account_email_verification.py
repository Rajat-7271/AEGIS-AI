"""Opaque single-use email-verification token primitives.

This module does not send mail or mutate login identities. Callers must
persist only the digest and enforce expiration/consumption transactionally.
"""

import hashlib
import re
import secrets
from datetime import datetime

_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")


def issue_email_verification_token() -> tuple[str, str]:
    """Return (secret for one-time delivery, SHA-256 digest for storage)."""
    token = secrets.token_urlsafe(32)
    return token, hash_email_verification_token(token)


def hash_email_verification_token(token: str) -> str:
    """Hash only well-formed 256-bit tokens; never persist or log the secret."""
    if not isinstance(token, str) or _TOKEN_RE.fullmatch(token) is None:
        raise ValueError("Invalid verification token")
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def normalize_proposed_email(value: str, *, current_email: str) -> str:
    """Validate a proposed login address without modifying the active identity.

    Domain comparison is case-insensitive; local-part case is preserved.
    Reject Unicode and whitespace until a deliberate SMTPUTF8 policy exists.
    """
    if not isinstance(value, str) or not isinstance(current_email, str):
        raise ValueError("Invalid email address")
    if len(value) > 254 or not value.isascii() or value != value.strip():
        raise ValueError("Invalid email address")
    local, sep, domain = value.rpartition("@")
    if not sep or not local or not domain or len(local) > 64:
        raise ValueError("Invalid email address")
    if local.startswith(".") or local.endswith(".") or ".." in local:
        raise ValueError("Invalid email address")
    if not re.fullmatch(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+", local):
        raise ValueError("Invalid email address")
    if len(domain) > 253 or "." not in domain:
        raise ValueError("Invalid email address")
    labels = domain.split(".")
    if any(
        not 1 <= len(label) <= 63
        or not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?", label)
        for label in labels
    ):
        raise ValueError("Invalid email address")
    normalized = f"{local}@{domain.lower()}"
    if normalized.casefold() == current_email.casefold():
        raise ValueError("New email must differ from current email")
    return normalized


def email_change_is_confirmable(
    *,
    now: datetime,
    expires_at: datetime,
    consumed_at: datetime | None,
    cancelled_at: datetime | None,
    original_email: str,
    current_email: str,
    active: bool,
) -> bool:
    """Fail closed before any transactional email update.

    The caller must also lock the request/user, verify its token digest,
    tenant/user binding and uniqueness, then consume it atomically.
    """
    timestamps = (now, expires_at, consumed_at, cancelled_at)
    if any(t is not None and (t.tzinfo is None or t.utcoffset() is None) for t in timestamps):
        return False
    if not active or consumed_at is not None or cancelled_at is not None:
        return False
    if now >= expires_at:
        return False
    if not original_email or original_email.casefold() != current_email.casefold():
        return False
    return True
