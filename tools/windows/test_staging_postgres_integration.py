"""Real PostgreSQL transaction tests; run only with isolated CI test database."""
import os
from pathlib import Path
import sys
import uuid

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from staging_postgres_receiver import accept_batch_postgres
from staging_receiver import InvalidBatch

psycopg = pytest.importorskip("psycopg")


def event(record, provider="Microsoft-Windows-Security-Auditing"):
    return {"System": {
        "EventID": 4624, "Channel": "Security", "Computer": "ci-host",
        "EventRecordID": record, "TimeCreated": "2026-11-13T00:00:00Z",
        "Provider": provider,
    }, "EventData": {}}


@pytest.fixture
def db():
    dsn = os.environ.get("AEGIS_WINDOWS_TEST_DATABASE_URL")
    if not dsn:
        pytest.skip("No isolated PostgreSQL test database configured")
    with psycopg.connect(dsn, autocommit=True) as conn:
        schema = (Path(__file__).parent / "staging_postgres_schema.sql").read_text()
        conn.execute(schema)
        yield conn


def test_real_postgres_atomic_replay_and_conflict(db):
    device = "ci-" + uuid.uuid4().hex
    first = {"device_id": device, "events": [event(1), event(2)]}
    assert accept_batch_postgres(db, first) == {"accepted": True, "last_record_id": 2}
    assert accept_batch_postgres(db, first) == {"accepted": True, "last_record_id": 2}
    with pytest.raises(InvalidBatch, match="Conflicting replay"):
        accept_batch_postgres(db, {"device_id": device, "events": [event(2, "different")]})
    with db.cursor() as cur:
        cur.execute("SELECT count(*) FROM windows_pilot.security_events WHERE device_id=%s", (device,))
        assert cur.fetchone()[0] == 2
    with pytest.raises(InvalidBatch, match="Conflicting replay"):
        accept_batch_postgres(db, {"device_id": device, "events": [event(1, "different"), event(3)]})
    with db.cursor() as cur:
        cur.execute("SELECT count(*) FROM windows_pilot.security_events WHERE device_id=%s", (device,))
        assert cur.fetchone()[0] == 2


def test_real_postgres_rolls_back_prior_insert_on_later_conflict(db):
    device = "ci-" + uuid.uuid4().hex
    accept_batch_postgres(db, {"device_id": device, "events": [event(20)]})
    # The first event is new; the second collides with an existing record.
    # The transaction must roll back the first insert on conflict.
    with pytest.raises(InvalidBatch, match="Conflicting replay"):
        accept_batch_postgres(db, {
            "device_id": device,
            "events": [event(10), event(20, "different")],
        })
    with db.cursor() as cur:
        cur.execute(
            "SELECT record_id FROM windows_pilot.security_events "
            "WHERE device_id=%s ORDER BY record_id", (device,)
        )
        assert [row[0] for row in cur.fetchall()] == [20]


def test_authenticated_http_to_real_postgres_and_replay(db):
    """Exercise actual loopback HTTP and committed PostgreSQL rows together."""
    import json
    import threading
    import urllib.error
    import urllib.request

    from staging_http_adapter import BoundedThreadingHTTPServer, handler_factory

    dsn = os.environ["AEGIS_WINDOWS_TEST_DATABASE_URL"]
    device = "ci-" + uuid.uuid4().hex
    token = "local-ci-test-token-" + uuid.uuid4().hex

    def persist(payload):
        with psycopg.connect(dsn, autocommit=True, connect_timeout=5) as connection:
            return accept_batch_postgres(connection, payload)

    server = BoundedThreadingHTTPServer(
        ("127.0.0.1", 0),
        handler_factory(Path("unused.sqlite"), token, device, persist_batch=persist),
    )
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()

    def post(payload, credential=token):
        url = f"http://127.0.0.1:{server.server_port}/v1/windows-security/events"
        request = urllib.request.Request(
            url, data=json.dumps(payload).encode("utf-8"), method="POST",
            headers={"Authorization": f"Bearer {credential}",
                     "Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                return response.status, json.load(response)
        except urllib.error.HTTPError as error:
            return error.code, None

    try:
        batch = {"device_id": device, "events": [event(100), event(101)]}
        assert post(batch, "wrong-token")[0] == 401
        assert post({**batch, "device_id": "spoofed"})[0] == 403
        expected = (200, {"accepted": True, "last_record_id": 101})
        assert post(batch) == expected
        assert post(batch) == expected
        conflict = {"device_id": device, "events": [event(101, "changed")]}
        assert post(conflict)[0] == 400
        with db.cursor() as cursor:
            cursor.execute(
                "SELECT record_id FROM windows_pilot.security_events "
                "WHERE device_id=%s ORDER BY record_id", (device,)
            )
            assert [row[0] for row in cursor.fetchall()] == [100, 101]
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)
