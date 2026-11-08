"""Opaque single-use email-verification token primitives.

This module does not send mail or mutate login identities. Callers must
persist only the digest and enforce expiration/consumption transactionally.
"""

import hashlib
import re
import secrets

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
