"""HTTP adapter contract tests using a real loopback server, no external network."""
import importlib.util
import json
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).parent
spec = importlib.util.spec_from_file_location("adapter", ROOT / "staging_http_adapter.py")
import sys
sys.path.insert(0, str(ROOT))
adapter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(adapter)


@pytest.fixture
def server(tmp_path):
    instance = ThreadingHTTPServer(
        ("127.0.0.1", 0),
        adapter.handler_factory(tmp_path / "events.sqlite", "a" * 32),
    )
    worker = threading.Thread(target=instance.serve_forever, daemon=True)
    worker.start()
    try:
        yield f"http://127.0.0.1:{instance.server_port}/v1/windows-security/events"
    finally:
        instance.shutdown()
        instance.server_close()
        worker.join(timeout=5)


def send(url, body, token="a" * 32, content_type="application/json"):
    req = urllib.request.Request(
        url, data=json.dumps(body).encode(),
        headers={"Authorization": f"Bearer {token}", "Content-Type": content_type},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as error:
        return error.code, None


def event(record):
    return {"System": {
        "EventID": 4624, "Channel": "Security", "Computer": "test",
        "EventRecordID": record, "TimeCreated": "2026-11-13T00:00:00Z",
        "Provider": "Microsoft-Windows-Security-Auditing",
    }, "EventData": {}}


def test_accept_and_replay(server):
    batch = {"device_id": "test-device", "events": [event(1), event(2)]}
    expected = (200, {"accepted": True, "last_record_id": 2})
    assert send(server, batch) == expected
    assert send(server, batch) == expected


def test_reject_unauthorized(server):
    assert send(server, {"device_id": "test", "events": [event(1)]}, token="bad")[0] == 401


def test_reject_private_fields(server):
    row = event(1)
    row["EventData"] = {"TargetUserName": "secret"}
    assert send(server, {"device_id": "test", "events": [row]})[0] == 400


def test_reject_wrong_content_type(server):
    assert send(server, {"device_id": "test", "events": [event(1)]}, content_type="text/plain")[0] == 415


def test_reject_device_spoofing(server):
    assert send(server, {"device_id": "other-device", "events": [event(1)]})[0] == 403


def test_reject_missing_device_id(server):
    assert send(server, {"events": [event(1)]})[0] == 403
