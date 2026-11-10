"""Account verification delivery tests (no network or real credentials)."""

from unittest.mock import AsyncMock

import pytest
from app.services.account_email_delivery import (
    send_email_change_security_notice,
    send_email_change_verification,
    verification_link,
)
from app.services.account_email_verification import issue_email_verification_token


@pytest.mark.parametrize(
    "origin",
    [
        "http://example.com",
        "https://user:password@example.com",
        "https://example.com/path",
        "https://example.com?next=evil",
        "https://example.com/#fragment",
        "https://example.com:8443",
        "https://example.com:invalid",
        "https://example.com:99999",
        "https://example.com\nmalicious",
    ],
)
def test_verification_link_rejects_untrusted_origins(origin):
    token, _ = issue_email_verification_token()
    with pytest.raises(ValueError):
        verification_link(origin=origin, token=token)


@pytest.mark.asyncio
async def test_verification_mail_uses_injected_sender_and_verified_origin():
    token, _ = issue_email_verification_token()
    mailer = AsyncMock()
    await send_email_change_verification(
        recipient="new@example.com",
        token=token,
        origin="https://console.example.com",
        mailer=mailer,
    )
    mailer.send.assert_awaited_once()
    kwargs = mailer.send.await_args.kwargs
    assert kwargs["to"] == ["new@example.com"]
    assert f"https://console.example.com/settings/verify-email?token={token}" in kwargs["text"]
    assert token in kwargs["html"]
    assert "Confirm your account email change" == kwargs["subject"]


@pytest.mark.asyncio
async def test_old_address_notice_has_no_token_and_escapes_html():
    mailer = AsyncMock()
    await send_email_change_security_notice(
        recipient="original@example.com",
        proposed_email="attacker+<tag>@example.com",
        mailer=mailer,
    )
    kwargs = mailer.send.await_args.kwargs
    assert kwargs["to"] == ["original@example.com"]
    assert "original@example.com" in kwargs["text"]
    assert "attacker+<tag>@example.com" in kwargs["text"]
    assert "&lt;tag&gt;" in kwargs["html"]
    assert "<tag>" not in kwargs["html"]
    assert "token=" not in kwargs["text"]
    assert "token=" not in kwargs["html"]
