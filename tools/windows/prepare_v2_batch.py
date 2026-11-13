"""Offline, read-only v2 batch preparation with fail-closed continuity gate.

No automatic epoch creation, checkpoint updates or network calls.
A caller must independently verify the log-instance marker before use.
"""
from __future__ import annotations

from pathlib import Path

from source_continuity import load_state, verify_observation, ContinuityError
from upload_security_events import load_batch, read_checkpoint
from upload_security_events_v2 import build_envelope


def prepare_batch(events_path: Path, continuity_path: Path,
                  upload_checkpoint: Path, *, trusted_log_instance: str,
                  newest_record_id: int) -> dict | None:
    state = load_state(continuity_path)
    verify_observation(
        state, log_instance=trusted_log_instance,
        newest_record_id=newest_record_id,
    )
    acknowledged = read_checkpoint(upload_checkpoint)
    if acknowledged < state["last_record_id"]:
        raise ContinuityError("Upload checkpoint behind verified continuity state")
    if acknowledged > newest_record_id:
        raise ContinuityError("Upload checkpoint exceeds observed Security log")
    events = load_batch(events_path, acknowledged)
    if not events:
        return None
    if events[-1]["System"]["EventRecordID"] > newest_record_id:
        raise ContinuityError("Export contains events beyond observed Security log")
    return build_envelope(state["device_id"], state["source_epoch"], events)
