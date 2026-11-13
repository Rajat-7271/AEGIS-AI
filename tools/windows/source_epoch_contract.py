"""Versioned Windows Security source identity contract (staging migration only).

This module does not alter existing exporter, uploader, or checkpoints.
An epoch must be assigned from verified source continuity, never regenerated
per polling cycle or inferred solely from EventRecordID.
"""
from __future__ import annotations

import re

EPOCH_PATTERN = re.compile(r"^[a-f0-9]{32}$")
DEVICE_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,128}$")


class SourceIdentityError(ValueError):
    pass


def validate_source_identity(identity: object) -> tuple[str, str, str]:
    """Validate a source identity provided by a future verified epoch manager."""
    if not isinstance(identity, dict) or set(identity) != {
        "device_id", "channel", "source_epoch"
    }:
        raise SourceIdentityError("Invalid source identity envelope")
    device, channel, epoch = (
        identity["device_id"], identity["channel"], identity["source_epoch"]
    )
    if not isinstance(device, str) or not DEVICE_PATTERN.fullmatch(device):
        raise SourceIdentityError("Invalid device identifier")
    if channel != "Security":
        raise SourceIdentityError("Unsupported event channel")
    if not isinstance(epoch, str) or not EPOCH_PATTERN.fullmatch(epoch):
        raise SourceIdentityError("Invalid source epoch")
    return device, channel, epoch


def validate_epoch_batch(payload: object) -> tuple[tuple[str, str, str], list[dict]]:
    """Require v2 identity and reuse strict v1 metadata validation."""
    from staging_receiver import validate

    if not isinstance(payload, dict) or set(payload) != {
        "protocol_version", "device_id", "channel", "source_epoch", "events"
    } or type(payload["protocol_version"]) is not int or payload["protocol_version"] != 2:
        raise SourceIdentityError("Invalid source-epoch protocol version")
    identity = {
        "device_id": payload["device_id"],
        "channel": payload["channel"],
        "source_epoch": payload["source_epoch"],
    }
    key = validate_source_identity(identity)
    device, events = validate({"device_id": payload["device_id"], "events": payload["events"]})
    if device != key[0] or any(event["System"]["Channel"] != key[1] for event in events):
        raise SourceIdentityError("Event source does not match identity")
    return key, events
