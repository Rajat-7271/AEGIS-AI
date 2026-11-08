"""Delivery adapter for account-email verification.

Never include a verification token in logs, metrics, exceptions, or audit records.
A successful provider response is not proof the recipient has verified ownership.
"""

from html import escape
from urllib.parse import quote, urlsplit

from app.services.email_approval import MailgunClient


def verification_link(*, origin: str, token: str) -> str:
    """Build a URL on a trusted, explicitly configured HTTPS origin."""
    from app.services.account_email_verification import hash_email_verification_token

    hash_email_verification_token(token)
    if not isinstance(origin, str) or not origin.startswith("https://"):
        raise ValueError("HTTPS account origin required")
    parsed = urlsplit(origin)
    if (
        not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path not in ("", "/")
        or parsed.port not in (None, 443)
        or any(c.isspace() for c in origin)
    ):
        raise ValueError("Invalid account origin")
    return f"{origin.rstrip('/')}/settings/verify-email?token={quote(token, safe='')}"


async def send_email_change_verification(
    *,
    recipient: str,
    token: str,
    origin: str,
    mailer: MailgunClient,
) -> None:
    """Send a one-time link; caller must persist its digest before dispatch."""
    link = verification_link(origin=origin, token=token)
    # Plain text deliberately avoids interpolating recipient-controlled HTML.
    await mailer.send(
        to=[recipient],
        subject="Confirm your account email change",
        text=(
            "A request was made to change your account login email. "
            "If this was you, confirm using the link below within 30 minutes. "
            "Otherwise ignore this message.\n\n"
            f"{link}\n"
        ),
        html=(
            "<p>A request was made to change your account login email.</p>"
            "<p>If this was you, confirm within 30 minutes using "
            f"<a href=\"{escape(link, quote=True)}\">this verification link</a>. "
            "Otherwise ignore this message.</p>"
        ),
    )
