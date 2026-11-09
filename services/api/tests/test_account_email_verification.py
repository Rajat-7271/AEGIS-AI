"""Token generation and storage invariants for pending email changes."""

import re
from datetime import UTC, datetime, timedelta

import pytest

from app.services.account_email_verification import (
    email_change_is_confirmable,
    hash_email_verification_token,
    issue_email_verification_token,
    normalize_proposed_email,
)


def test_email_verification_token_is_opaque_and_hash_only_is_persistable():
    token, digest = issue_email_verification_token()
    assert re.fullmatch(r"[A-Za-z0-9_-]{43}", token)
    assert re.fullmatch(r"[0-9a-f]{64}", digest)
    assert token != digest
    assert hash_email_verification_token(token) == digest


def test_new_requests_receive_independent_tokens():
    issued = [issue_email_verification_token() for _ in range(20)]
    assert len({token for token, _ in issued}) == len(issued)
    assert len({digest for _, digest in issued}) == len(issued)


@pytest.mark.parametrize("token", ["", "abc", "!" * 43, "a" * 44, None, 123])
def test_malformed_email_verification_tokens_are_rejected(token):
    with pytest.raises(ValueError, match="Invalid verification token"):
        hash_email_verification_token(token)


@pytest.mark.parametrize(
    ("candidate", "expected"),
    [
        ("new@example.com", "new@example.com"),
        ("first.last+alerts@EXAMPLE.COM", "first.last+alerts@example.com"),
    ],
)
def test_proposed_email_validation(candidate, expected):
    assert normalize_proposed_email(candidate, current_email="old@example.com") == expected


@pytest.mark.parametrize(
    "candidate",
    [
        "", "old@example.com", "OLD@EXAMPLE.COM", " no@example.com",
        "no@example.com ", "bad@@example.com", "a..b@example.com",
        ".bad@example.com", "bad.@example.com", "bad@-example.com",
        "bad@example..com", "bad@example", "tést@example.com",
        "bad\n@example.com", "bad@localhost", "bad@exam_ple.com",
        "x" * 65 + "@example.com",
    ],
)
def test_invalid_or_unchanged_proposed_email_is_rejected(candidate):
    with pytest.raises(ValueError):
        normalize_proposed_email(candidate, current_email="old@example.com")


def test_email_confirmation_requires_active_unexpired_unchanged_identity():
    now = datetime.now(UTC)
    args = {
        "now": now,
        "expires_at": now + timedelta(minutes=30),
        "consumed_at": None,
        "cancelled_at": None,
        "original_email": "old@example.com",
        "current_email": "old@example.com",
        "active": True,
    }
    assert email_change_is_confirmable(**args)
    for changes in (
        {"expires_at": now},
        {"expires_at": now - timedelta(seconds=1)},
        {"consumed_at": now},
        {"cancelled_at": now},
        {"current_email": "different@example.com"},
        {"active": False},
        {"now": now.replace(tzinfo=None)},
        {"expires_at": (now + timedelta(minutes=30)).replace(tzinfo=None)},
    ):
        assert not email_change_is_confirmable(**(args | changes))
