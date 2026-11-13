"""Offline v2 batch preparation; no real Windows events or network."""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from prepare_v2_batch import prepare_batch
from source_continuity import ContinuityError, write_new_state


def event(record):
    return {"System": {
        "EventID": 4624, "Channel": "Security", "Computer": "ci-host",
        "EventRecordID": record, "TimeCreated": "2026-11-13T00:00:00Z",
        "Provider": "Microsoft-Windows-Security-Auditing",
    }, "EventData": {}}


def inputs(tmp_path):
    events = tmp_path / "events.jsonl"
    events.write_text("".join(json.dumps(event(n)) + "\n" for n in (101, 102)))
    state = tmp_path / "continuity.json"
    write_new_state(state, {
        "version": 1, "device_id": "ci-device", "channel": "Security",
        "source_epoch": "a" * 32, "log_instance": "trusted-instance",
        "last_record_id": 100,
    })
    checkpoint = tmp_path / "upload.checkpoint"
    checkpoint.write_text("100")
    return events, state, checkpoint


def test_prepares_envelope_without_mutating_inputs(tmp_path):
    paths = inputs(tmp_path)
    before = [p.read_bytes() for p in paths]
    envelope = prepare_batch(*paths, trusted_log_instance="trusted-instance",
                             newest_record_id=102)
    assert envelope["protocol_version"] == 2
    assert [e["System"]["EventRecordID"] for e in envelope["events"]] == [101, 102]
    assert [p.read_bytes() for p in paths] == before


def test_rejects_marker_change_even_with_higher_record_id(tmp_path):
    with pytest.raises(ContinuityError, match="instance changed"):
        prepare_batch(*inputs(tmp_path), trusted_log_instance="reset-instance",
                      newest_record_id=999)


def test_rejects_checkpoint_behind_verified_state(tmp_path):
    paths = inputs(tmp_path)
    paths[2].write_text("99")
    with pytest.raises(ContinuityError, match="behind"):
        prepare_batch(*paths, trusted_log_instance="trusted-instance",
                      newest_record_id=102)


def test_rejects_unobserved_export_tail(tmp_path):
    with pytest.raises(ContinuityError, match="beyond observed"):
        prepare_batch(*inputs(tmp_path), trusted_log_instance="trusted-instance",
                      newest_record_id=101)
