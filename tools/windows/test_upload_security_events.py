"""Offline safety tests for the opt-in Windows staging sender."""
import importlib.util
import json
from pathlib import Path

import pytest

SCRIPT = Path(__file__).with_name("upload_security_events.py")
spec = importlib.util.spec_from_file_location("windows_sender", SCRIPT)
sender = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sender)


def event(record, extra=None):
    value = {"System": {
        "EventID": 4624, "Channel": "Security", "Computer": "test-pc",
        "EventRecordID": record, "TimeCreated": "2026-11-13T00:00:00Z",
        "Provider": "Microsoft-Windows-Security-Auditing",
    }, "EventData": {}}
    if extra:
        value.update(extra)
    return value


def write_events(tmp_path, rows):
    path = tmp_path / "events.jsonl"
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    return path


def test_batch_respects_upload_checkpoint(tmp_path):
    path = write_events(tmp_path, [event(10), event(11), event(12)])
    assert [x["System"]["EventRecordID"] for x in sender.load_batch(path, 10)] == [11, 12]


@pytest.mark.parametrize("rows", [
    [event(10), event(10)],
    [event(12), event(11)],
    [event(10, {"Password": "secret"})],
    [{**event(10), "EventData": {"TargetUserName": "private"}}],
    [{**event(10), "System": {**event(10)["System"], "CommandLine": "private"}}],
])
def test_rejects_duplicates_ordering_and_private_fields(tmp_path, rows):
    with pytest.raises(ValueError):
        sender.load_batch(write_events(tmp_path, rows), 0)


def test_checkpoint_roundtrip(tmp_path):
    checkpoint = tmp_path / "upload.checkpoint"
    sender.save_checkpoint(checkpoint, 42)
    assert sender.read_checkpoint(checkpoint) == 42


def test_rejects_insecure_endpoint_without_network():
    with pytest.raises(ValueError, match="HTTPS"):
        sender.send_batch("http://example.com/ingest", "token", "device", [event(1)])


def test_rejects_device_id_spoofing_without_network():
    with pytest.raises(ValueError, match="device identifier"):
        sender.send_batch("https://example.com/ingest", "token", "../other", [event(1)])


def test_rejects_nonstandard_https_port_without_network():
    with pytest.raises(ValueError, match="HTTPS"):
        sender.send_batch("https://example.com:8080/ingest", "token", "device", [event(1)])


def test_rejects_oversized_batch_without_network():
    with pytest.raises(ValueError, match="batch size"):
        sender.send_batch("https://example.com/ingest", "token", "device", [event(i) for i in range(1, 102)])


def test_acknowledgement_must_match_last_record(monkeypatch):
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
            assert request.get_method() == "POST"
            assert request.get_header("Authorization") == "Bearer token"
            return FakeResponse(self.ack)

    monkeypatch.setattr(sender.urllib.request, "build_opener", lambda *args: FakeOpener({"accepted": True, "last_record_id": 2}))
    assert sender.send_batch("https://example.com/ingest", "token", "device", [event(1), event(2)]) == 2

    monkeypatch.setattr(sender.urllib.request, "build_opener", lambda *args: FakeOpener({"accepted": True, "last_record_id": 999}))
    with pytest.raises(ValueError, match="acknowledgement"):
        sender.send_batch("https://example.com/ingest", "token", "device", [event(1), event(2)])
