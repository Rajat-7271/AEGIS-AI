"""Offline transactional receiver tests; no network or production dependencies."""
import importlib.util
import sqlite3
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location(
    "staging_receiver", Path(__file__).with_name("staging_receiver.py")
)
receiver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(receiver)


def make_event(record, event_id=4624):
    return {
        "System": {
            "EventID": event_id, "Channel": "Security",
            "Computer": "test-pc", "EventRecordID": record,
            "TimeCreated": "2026-11-13T10:00:00Z",
            "Provider": "Microsoft-Windows-Security-Auditing",
        },
        "EventData": {},
    }


def payload(*events):
    return {"device_id": "test-device", "events": list(events)}


def count(db):
    with sqlite3.connect(db) as conn:
        return conn.execute("SELECT COUNT(*) FROM windows_security_events").fetchone()[0]


def test_persists_and_acknowledges_only_committed_batch(tmp_path):
    db = tmp_path / "events.sqlite"
    ack = receiver.accept_batch(db, payload(make_event(10), make_event(11)))
    assert ack == {"accepted": True, "last_record_id": 11}
    assert count(db) == 2
    assert receiver.accept_batch(db, payload(make_event(10), make_event(11))) == ack
    assert count(db) == 2


def test_replay_with_conflicting_contents_rejected_atomically(tmp_path):
    db = tmp_path / "events.sqlite"
    receiver.accept_batch(db, payload(make_event(10)))
    changed = make_event(10, 4672)
    with pytest.raises(receiver.InvalidBatch, match="Conflicting"):
        receiver.accept_batch(db, payload(make_event(9), changed))
    assert count(db) == 1


@pytest.mark.parametrize("bad", [
    payload(),
    payload(make_event(3), make_event(3)),
    payload(make_event(3), make_event(2)),
    payload({**make_event(1), "EventData": {"TargetUserName": "private"}}),
    payload({**make_event(1), "unexpected": "private"}),
    payload({**make_event(1), "System": {**make_event(1)["System"], "EventID": 9999}}),
    {"device_id": "../unsafe", "events": [make_event(1)]},
])
def test_invalid_batches_never_persist(tmp_path, bad):
    db = tmp_path / "events.sqlite"
    with pytest.raises(receiver.InvalidBatch):
        receiver.accept_batch(db, bad)
    if db.exists():
        assert count(db) == 0


def test_device_token_check():
    receiver.authorize("correct", "correct")
    for provided in ("", "incorrect"):
        with pytest.raises(PermissionError):
            receiver.authorize(provided, "correct")


def test_duplicate_replay_does_not_increase_rows(tmp_path):
    db = tmp_path / "events.sqlite"
    first = payload(make_event(101), make_event(102))
    receiver.accept_batch(db, first)
    receiver.accept_batch(db, first)
    receiver.accept_batch(db, payload(make_event(102), make_event(103)))
    assert count(db) == 3


def test_invalid_later_event_does_not_partially_persist(tmp_path):
    db = tmp_path / "events.sqlite"
    first = make_event(201)
    second = make_event(202)
    second["EventData"] = {"CommandLine": "private"}
    with pytest.raises(receiver.InvalidBatch):
        receiver.accept_batch(db, payload(first, second))
    assert not db.exists() or count(db) == 0
