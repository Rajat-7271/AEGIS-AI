"""Offline source epoch protocol contract tests."""
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from source_epoch_contract import SourceIdentityError, validate_epoch_batch


def batch(epoch="a" * 32, version=2):
    return {
        "protocol_version": version,
        "device_id": "ci-device",
        "channel": "Security",
        "source_epoch": epoch,
        "events": [{
            "System": {
                "EventID": 4624, "Channel": "Security",
                "Computer": "ci-host", "EventRecordID": 1,
                "TimeCreated": "2026-11-13T00:00:00Z",
                "Provider": "Microsoft-Windows-Security-Auditing",
            },
            "EventData": {},
        }],
    }


def test_valid_v2_identity():
    key, events = validate_epoch_batch(batch())
    assert key == ("ci-device", "Security", "a" * 32)
    assert len(events) == 1


@pytest.mark.parametrize("epoch", ["", "a" * 31, "z" * 32, "../unsafe", "A" * 32])
def test_invalid_epochs_rejected(epoch):
    with pytest.raises(SourceIdentityError):
        validate_epoch_batch(batch(epoch=epoch))


def test_v1_cannot_silently_enter_v2():
    with pytest.raises(SourceIdentityError):
        validate_epoch_batch(batch(version=1))


def test_private_fields_still_rejected():
    payload = batch()
    payload["events"][0]["EventData"] = {"TargetUserName": "private"}
    with pytest.raises(ValueError):
        validate_epoch_batch(payload)


def test_channel_mismatch_rejected():
    payload = batch()
    payload["channel"] = "System"
    with pytest.raises(SourceIdentityError):
        validate_epoch_batch(payload)
