"""Token generation and storage invariants for pending email changes."""

import re

import pytest
from app.services.account_email_verification import (
    hash_email_verification_token,
    issue_email_verification_token,
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
