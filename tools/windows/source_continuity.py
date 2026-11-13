"""Fail-closed continuity state for a future Windows Security epoch manager.

No event log access, checkpoint migration, or implicit epoch creation.
The caller must provide a trusted stable log-instance identifier obtained
independently of EventRecordID; this code cannot establish that trust.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import tempfile

from source_epoch_contract import validate_source_identity

MARKER = re.compile(r"^[A-Za-z0-9._:-]{1,256}$")


class ContinuityError(ValueError):
    pass


def _check_marker(value):
    if not isinstance(value, str) or not MARKER.fullmatch(value):
        raise ContinuityError("Missing or invalid trusted log-instance marker")
    return value


def validate_state(state):
    if not isinstance(state, dict) or set(state) != {
        "version", "device_id", "channel", "source_epoch",
        "log_instance", "last_record_id"
    } or type(state["version"]) is not int or state["version"] != 1:
        raise ContinuityError("Invalid continuity state")
    validate_source_identity({
        "device_id": state["device_id"], "channel": state["channel"],
        "source_epoch": state["source_epoch"]
    })
    _check_marker(state["log_instance"])
    if type(state["last_record_id"]) is not int or state["last_record_id"] < 0:
        raise ContinuityError("Invalid last record ID")
    return state


def verify_observation(state, *, log_instance, newest_record_id):
    """Verify known state; never silently rotate an epoch on reset."""
    state = validate_state(state)
    _check_marker(log_instance)
    if type(newest_record_id) is not int or newest_record_id < 0:
        raise ContinuityError("Invalid observed record ID")
    if log_instance != state["log_instance"]:
        raise ContinuityError("Security log instance changed; manual recovery required")
    if newest_record_id < state["last_record_id"]:
        raise ContinuityError("Security log record ID regressed; manual recovery required")
    return state


def load_state(path):
    path = Path(path)
    if path.is_symlink():
        raise ContinuityError("Refusing symlink continuity state")
    try:
        with path.open("r", encoding="utf-8") as handle:
            return validate_state(json.load(handle))
    except (OSError, ValueError, TypeError) as exc:
        raise ContinuityError("Missing or invalid continuity state; manual recovery required") from exc


def write_new_state(path, state):
    """Create only; never overwrite or auto-repair a checkpoint."""
    state = validate_state(state)
    path = Path(path)
    if path.is_symlink():
        raise ContinuityError("Refusing symlink continuity state")
    path.parent.mkdir(parents=True, exist_ok=True)
    data = (json.dumps(state, sort_keys=True, separators=(",", ":")) + "\n").encode()
    # Exclusive create prevents accidentally rotating an existing epoch.
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError as exc:
        raise ContinuityError("Continuity state already exists; refusing overwrite") from exc
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        # Leave partial file in place for manual investigation.
        raise
    return state
