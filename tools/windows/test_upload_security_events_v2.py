"""Offline checks for v2 HTTPS sender contract; no network access."""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from source_epoch_contract import SourceIdentityError
from upload_security_events_v2 import build_envelope, send_epoch_batch


def event(record=7):
    return {"System": {
        "EventID": 4624, "Channel": "Security", "Computer": "ci-host",
        "EventRecordID": record, "TimeCreated": "2026-11-13T00:00:00Z",
        "Provider": "Microsoft-Windows-Security-Auditing",
    }, "EventData": {}}


def test_build_v2_envelope():
    envelope = build_envelope("ci-device", "a" * 32, [event()])
    assert envelope["protocol_version"] == 2
    assert envelope["source_epoch"] == "a" * 32


def test_invalid_epoch_fails_before_network(monkeypatch):
    monkeypatch.setattr("urllib.request.build_opener", lambda *args: pytest.fail("network attempted"))
    with pytest.raises(SourceIdentityError):
        send_epoch_batch("https://example.com/ingest", "x" * 32,
                         build_envelope("ci-device", "a" * 32, [event()]) | {"source_epoch": "invalid"})


def test_insecure_url_fails_before_network():
    with pytest.raises(ValueError, match="HTTPS"):
        send_epoch_batch("http://example.com/ingest", "x" * 32,
                         build_envelope("ci-device", "a" * 32, [event()]))


def test_valid_ack_and_rejected_mismatch(monkeypatch):
    seen = []

    class FakeResponse:
        status = 200
        def __init__(self, ack):
            self.ack = ack
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return False
        def read(self, size):
            return json.dumps(self.ack).encode()

    class FakeOpener:
        def __init__(self, ack):
            self.ack = ack
        def open(self, request, timeout):
            seen.append(json.loads(request.data))
            return FakeResponse(self.ack)

    envelope = build_envelope("ci-device", "a" * 32, [event()])
    monkeypatch.setattr("urllib.request.build_opener",
                        lambda *args: FakeOpener({"accepted": True, "last_record_id": 7}))
    assert send_epoch_batch("https://example.com/ingest", "x" * 32, envelope) == 7
    assert seen[0] == envelope

    monkeypatch.setattr("urllib.request.build_opener",
                        lambda *args: FakeOpener({"accepted": True, "last_record_id": 8}))
    with pytest.raises(ValueError, match="acknowledgement"):
        send_epoch_batch("https://example.com/ingest", "x" * 32, envelope)
