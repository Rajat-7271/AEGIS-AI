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
