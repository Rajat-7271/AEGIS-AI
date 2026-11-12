"""Regression tests for the scheduler's checkpoint acknowledgement gate.

A partial or malformed response must never be interpreted as complete.
"""
import pytest

from app.scheduler import _acknowledgement_complete


@pytest.mark.parametrize(
    ("result", "sent", "expected"),
    [
        ({"accepted": 2, "rejected": 0}, 2, True),
        ({"accepted": 0, "rejected": 0}, 0, True),
        ({"accepted": 1, "rejected": 1}, 2, False),
        ({"accepted": 0, "rejected": 2}, 2, False),
        ({"accepted": 1, "rejected": 0}, 2, False),
        ({"accepted": 3, "rejected": 0}, 2, False),
        ({"accepted": -1, "rejected": 0}, 2, False),
        ({"accepted": True, "rejected": 0}, 1, False),
        ({"accepted": "2", "rejected": 0}, 2, False),
        ({"accepted": 2, "rejected": False}, 2, False),
        ({"accepted": 2}, 2, False),
        ({"rejected": 0}, 2, False),
        ({}, 2, False),
        (None, 2, False),
        ([], 2, False),
    ],
)
def test_acknowledgement_gate(result, sent, expected):
    assert _acknowledgement_complete(result, sent) is expected
