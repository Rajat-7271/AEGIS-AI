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
    assert send(server, {"device_id": "test-device", "events": [row]})[0] == 400


def test_reject_wrong_content_type(server):
    assert send(server, {"device_id": "test", "events": [event(1)]}, content_type="text/plain")[0] == 415


def test_reject_device_spoofing(server):
    assert send(server, {"device_id": "other-device", "events": [event(1)]})[0] == 403


def test_reject_missing_device_id(server):
    assert send(server, {"events": [event(1)]})[0] == 403


def test_rate_limit_rejects_excess_authenticated_requests(tmp_path):
    instance = ThreadingHTTPServer(
        ("127.0.0.1", 0),
        adapter.handler_factory(tmp_path / "rate.sqlite", "a" * 32, "test-device", max_requests_per_minute=1),
    )
    worker = threading.Thread(target=instance.serve_forever, daemon=True)
    worker.start()
    try:
        url = f"http://127.0.0.1:{instance.server_port}/v1/windows-security/events"
        body = {"device_id": "test-device", "events": [event(1)]}
        assert send(url, body)[0] == 200
        assert send(url, body)[0] == 429
        assert send(url, body, token="incorrect")[0] == 401
    finally:
        instance.shutdown()
        instance.server_close()
        worker.join(timeout=5)


def test_rate_limit_configuration_rejects_zero(tmp_path):
    with pytest.raises(ValueError, match="Rate limit"):
        adapter.handler_factory(tmp_path / "rate.sqlite", "a" * 32, max_requests_per_minute=0)


def test_bounded_server_configures_client_socket_timeout(tmp_path):
    instance = adapter.BoundedThreadingHTTPServer(
        ("127.0.0.1", 0),
        adapter.handler_factory(tmp_path / "timeout.sqlite", "a" * 32),
    )
    try:
        assert instance.daemon_threads is True
        assert instance.block_on_close is False
        assert instance.request_queue_size == 16
        assert instance.client_timeout_seconds == 10
    finally:
        instance.server_close()


def test_injected_storage_receives_only_authenticated_device(tmp_path):
    accepted = []
    def persist(payload):
        accepted.append(payload)
        return {"accepted": True, "last_record_id": payload["events"][-1]["System"]["EventRecordID"]}

    instance = ThreadingHTTPServer(
        ("127.0.0.1", 0),
        adapter.handler_factory(tmp_path / "unused.sqlite", "a" * 32,
                                "test-device", persist_batch=persist),
    )
    worker = threading.Thread(target=instance.serve_forever, daemon=True)
    worker.start()
    try:
        url = f"http://127.0.0.1:{instance.server_port}/v1/windows-security/events"
        batch = {"device_id": "test-device", "events": [event(51)]}
        assert send(url, batch, token="wrong")[0] == 401
        assert send(url, {"device_id": "wrong-device", "events": [event(51)]})[0] == 403
        assert accepted == []
        assert send(url, batch) == (200, {"accepted": True, "last_record_id": 51})
        assert accepted == [batch]
    finally:
        instance.shutdown()
        instance.server_close()
        worker.join(timeout=5)


def test_injected_storage_failure_does_not_acknowledge(tmp_path):
    def fail(_payload):
        raise RuntimeError("Database unavailable")

    instance = ThreadingHTTPServer(
        ("127.0.0.1", 0),
        adapter.handler_factory(tmp_path / "unused.sqlite", "a" * 32,
                                "test-device", persist_batch=fail),
    )
    worker = threading.Thread(target=instance.serve_forever, daemon=True)
    worker.start()
    try:
        url = f"http://127.0.0.1:{instance.server_port}/v1/windows-security/events"
        assert send(url, {"device_id": "test-device", "events": [event(52)]})[0] == 500
    finally:
        instance.shutdown()
        instance.server_close()
        worker.join(timeout=5)
