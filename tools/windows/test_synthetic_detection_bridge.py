"""Disposable ledger and actual loopback HTTP; all inputs are synthetic."""

import copy
import json
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from uuid import uuid4

import pytest
from synthetic_detection_bridge import SyntheticBridge


def fixture():
    return {
        "synthetic": True,
        "batch": {
            "protocol_version": 2,
            "device_id": "synthetic-device",
            "channel": "Security",
            "source_epoch": "a" * 32,
            "events": [
                {
                    "System": {
                        "EventID": 1102,
                        "Channel": "Security",
                        "Computer": "synthetic-host",
                        "EventRecordID": 1,
                        "TimeCreated": "2026-11-13T00:00:00Z",
                        "Provider": "Microsoft-Windows-Security-Auditing",
                    },
                    "EventData": {},
                }
            ],
        },
    }


def test_opt_in_and_fixture_boundary(tmp_path):
    with pytest.raises(ValueError, match="opt-in"):
        SyntheticBridge(tmp_path / "disabled")
    assert not (tmp_path / "disabled").exists()
    bridge = SyntheticBridge(tmp_path / "ledger", enabled=True)
    for value in ({"batch": fixture()["batch"]}, {**fixture(), "synthetic": False}):
        with pytest.raises(ValueError):
            bridge.enqueue(value, bindings={}, connector=str(uuid4()))
    with pytest.raises(KeyError):
        bridge.enqueue(fixture(), bindings={}, connector=str(uuid4()))
    bad = fixture()
    bad["batch"]["tenant_id"] = str(uuid4())
    with pytest.raises(ValueError):
        bridge.enqueue(bad, bindings={}, connector=str(uuid4()))


def test_concurrent_enqueue_keeps_one_row(tmp_path):
    bridge = SyntheticBridge(tmp_path / "ledger", enabled=True)
    tenant, connector = str(uuid4()), str(uuid4())

    def enqueue(_):
        return bridge.enqueue(fixture(), bindings={"synthetic-device": tenant}, connector=connector)

    with ThreadPoolExecutor(max_workers=4) as pool:
        assert sum(pool.map(enqueue, range(8))) == 1
    with bridge.connect() as db:
        assert db.execute("SELECT count(*) FROM delivery").fetchone()[0] == 1


def test_identity_conflicts_and_atomic_rollback(tmp_path):
    bridge = SyntheticBridge(tmp_path / "ledger", enabled=True)
    tenant, connector = str(uuid4()), str(uuid4())
    bindings = {"synthetic-device": tenant, "other-device": tenant}

    def enqueue(value):
        return bridge.enqueue(value, bindings=bindings, connector=connector)

    assert enqueue(fixture()) == 1
    assert enqueue(fixture()) == 0
    with pytest.raises(ValueError, match="binding"):
        bridge.enqueue(fixture(), bindings={"synthetic-device": str(uuid4())}, connector=connector)
    for field, value in (("device_id", "other-device"), ("source_epoch", "b" * 32)):
        changed = fixture()
        changed["batch"][field] = value
        assert enqueue(changed) == 1
    for field, value in (("Computer", "other-host"), ("EventRecordID", 2)):
        changed = fixture()
        changed["batch"]["events"][0]["System"][field] = value
        assert enqueue(changed) == 1
    changed = fixture()
    changed["batch"]["events"][0]["System"]["EventID"] = 4624
    before = copy.deepcopy(changed["batch"]["events"][0])
    before["System"]["Computer"] = "new-host"
    before["System"]["EventRecordID"] = 0
    # Valid ordering: a new identity then a conflicting identity.
    changed["batch"]["events"][0]["System"]["EventRecordID"] = 2
    before["System"]["EventRecordID"] = 1
    changed["batch"]["events"].insert(0, before)
    with pytest.raises(ValueError, match="Conflicting"):
        enqueue(changed)
    with bridge.connect() as db:
        assert db.execute("SELECT count(*) FROM delivery").fetchone()[0] == 5


def test_http_retry_restart_tenant_and_ack_failure(tmp_path):
    tenant, other, connector = str(uuid4()), str(uuid4()), str(uuid4())
    received = []
    replies = [{"accepted": 0, "rejected": 1}, {"accepted": 1, "rejected": 0}]

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            assert self.path == "/v1/ingest/batch"
            assert self.headers["Authorization"] == "Bearer synthetic-token"
            assert self.headers["X-Tenant-ID"] == tenant
            received.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(json.dumps(replies[min(len(received) - 1, 1)]).encode())

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    path = tmp_path / "ledger"
    bridge = SyntheticBridge(path, enabled=True)
    bridge.enqueue(fixture(), bindings={"synthetic-device": tenant}, connector=connector)
    endpoint = f"http://127.0.0.1:{server.server_port}/v1/ingest/batch"

    def deliver(scope=tenant):
        return bridge.deliver_one(tenant=scope, connector=connector, endpoint=endpoint, token="synthetic-token")

    try:
        assert deliver(other) is False
        assert received == []
        with pytest.raises(ValueError, match="complete"):
            deliver()
        with bridge.connect() as db:
            db.execute("CREATE TRIGGER fail_ack BEFORE UPDATE ON delivery BEGIN SELECT RAISE(ABORT,'synthetic disk error'); END")
        with pytest.raises(sqlite3.IntegrityError):
            deliver()
        bridge = SyntheticBridge(path, enabled=True)
        with bridge.connect() as db:
            db.execute("DROP TRIGGER fail_ack")
        assert deliver() is True
        assert received[0] == received[1] == received[2]
        event = received[2]["events"][0]
        assert json.loads(event["external_id"].split(":", 1)[1]) == event["raw_event"]["receipt_identity"]
        assert deliver() is False
        assert bridge.enqueue(fixture(), bindings={"synthetic-device": tenant}, connector=connector) == 0
        assert deliver() is False
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


@pytest.mark.parametrize(
    "endpoint", ["https://staging.invalid/v1/ingest/batch", "http://localhost/v1/ingest/batch", "http://127.0.0.1/v1/ingest/batch?x=1"]
)
def test_remote_endpoints_forbidden(tmp_path, endpoint):
    bridge = SyntheticBridge(tmp_path / "ledger", enabled=True)
    with pytest.raises(ValueError, match="loopback"):
        bridge.deliver_one(tenant=str(uuid4()), connector=str(uuid4()), endpoint=endpoint, token="synthetic-token")
