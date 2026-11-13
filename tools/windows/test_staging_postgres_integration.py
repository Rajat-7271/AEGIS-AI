"""Real PostgreSQL transaction tests; run only with isolated CI test database."""

import os
import sys
import uuid
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from staging_postgres_receiver import accept_batch_postgres
from staging_receiver import InvalidBatch

psycopg = pytest.importorskip("psycopg")


def event(record, provider="Microsoft-Windows-Security-Auditing"):
    return {
        "System": {
            "EventID": 4624,
            "Channel": "Security",
            "Computer": "ci-host",
            "EventRecordID": record,
            "TimeCreated": "2026-11-13T00:00:00Z",
            "Provider": provider,
        },
        "EventData": {},
    }


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
        accept_batch_postgres(
            db,
            {
                "device_id": device,
                "events": [event(10), event(20, "different")],
            },
        )
    with db.cursor() as cur:
        cur.execute("SELECT record_id FROM windows_pilot.security_events WHERE device_id=%s ORDER BY record_id", (device,))
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
            url,
            data=json.dumps(payload).encode("utf-8"),
            method="POST",
            headers={"Authorization": f"Bearer {credential}", "Content-Type": "application/json"},
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
            cursor.execute("SELECT record_id FROM windows_pilot.security_events WHERE device_id=%s ORDER BY record_id", (device,))
            assert [row[0] for row in cursor.fetchall()] == [100, 101]
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)


def test_real_postgres_concurrent_identical_replays(db):
    """Two simultaneous transactions must not duplicate the same event."""
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier

    dsn = os.environ["AEGIS_WINDOWS_TEST_DATABASE_URL"]
    device = "ci-" + uuid.uuid4().hex
    payload = {"device_id": device, "events": [event(300), event(301)]}
    barrier = Barrier(2)

    def submit(_):
        with psycopg.connect(dsn, autocommit=True, connect_timeout=5) as connection:
            barrier.wait(timeout=10)
            return accept_batch_postgres(connection, payload)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(submit, range(2)))
    assert results == [{"accepted": True, "last_record_id": 301}] * 2
    with db.cursor() as cursor:
        cursor.execute(
            "SELECT count(*) FROM windows_pilot.security_events WHERE device_id=%s",
            (device,),
        )
        assert cursor.fetchone()[0] == 2


def test_epoch_scoped_postgres_replay_and_record_reuse(db):
    """A new epoch may safely reuse a record ID without colliding with the old one."""
    from source_epoch_contract import SourceIdentityError
    from staging_postgres_epoch_receiver import accept_epoch_batch_postgres

    db.execute((Path(__file__).parent / "staging_postgres_epoch_schema.sql").read_text())
    device = "ci-" + uuid.uuid4().hex

    def payload(epoch, provider="Microsoft-Windows-Security-Auditing"):
        return {
            "protocol_version": 2,
            "device_id": device,
            "channel": "Security",
            "source_epoch": epoch,
            "events": [event(1, provider)],
        }

    first = payload("a" * 32)
    second = payload("b" * 32)
    expected = {"accepted": True, "last_record_id": 1}
    assert accept_epoch_batch_postgres(db, first) == expected
    assert accept_epoch_batch_postgres(db, first) == expected
    assert accept_epoch_batch_postgres(db, second) == expected

    with pytest.raises(InvalidBatch, match="Conflicting replay"):
        accept_epoch_batch_postgres(db, payload("a" * 32, "different"))
    with pytest.raises(SourceIdentityError):
        accept_epoch_batch_postgres(db, {**first, "source_epoch": "bad"})

    with db.cursor() as cursor:
        cursor.execute(
            "SELECT source_epoch, count(*) FROM windows_pilot.security_events_v2 "
            "WHERE device_id=%s GROUP BY source_epoch ORDER BY source_epoch",
            (device,),
        )
        assert [(row[0].strip(), row[1]) for row in cursor.fetchall()] == [("a" * 32, 1), ("b" * 32, 1)]


def test_epoch_postgres_rollback_on_later_conflict(db):
    from staging_postgres_epoch_receiver import accept_epoch_batch_postgres

    db.execute((Path(__file__).parent / "staging_postgres_epoch_schema.sql").read_text())
    device = "ci-" + uuid.uuid4().hex
    identity = {
        "protocol_version": 2,
        "device_id": device,
        "channel": "Security",
        "source_epoch": "c" * 32,
    }
    accept_epoch_batch_postgres(db, {**identity, "events": [event(20)]})
    with pytest.raises(InvalidBatch, match="Conflicting replay"):
        accept_epoch_batch_postgres(
            db,
            {
                **identity,
                "events": [event(10), event(20, "changed")],
            },
        )
    with db.cursor() as cursor:
        cursor.execute(
            "SELECT record_id FROM windows_pilot.security_events_v2 WHERE device_id=%s ORDER BY record_id",
            (device,),
        )
        assert [row[0] for row in cursor.fetchall()] == [20]


def test_epoch_http_postgres_ingestion_and_replay(db):
    """Exercise authenticated local v2 HTTP through committed epoch-scoped rows."""
    import json
    import threading
    import urllib.error
    import urllib.request

    from staging_http_adapter import BoundedThreadingHTTPServer
    from staging_postgres_epoch_http_adapter import epoch_handler_factory
    from staging_postgres_epoch_receiver import accept_epoch_batch_postgres

    db.execute((Path(__file__).parent / "staging_postgres_epoch_schema.sql").read_text())
    dsn = os.environ["AEGIS_WINDOWS_TEST_DATABASE_URL"]
    device = "ci-" + uuid.uuid4().hex
    token = "local-test-" + uuid.uuid4().hex

    def persist(payload):
        with psycopg.connect(dsn, autocommit=True, connect_timeout=5) as connection:
            return accept_epoch_batch_postgres(connection, payload)

    server = BoundedThreadingHTTPServer(("127.0.0.1", 0), epoch_handler_factory(token, device, persist))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    def post(payload, credential=token):
        request = urllib.request.Request(
            f"http://127.0.0.1:{server.server_port}/v1/windows-security/events",
            data=json.dumps(payload).encode("utf-8"),
            method="POST",
            headers={"Authorization": f"Bearer {credential}", "Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                return response.status, json.load(response)
        except urllib.error.HTTPError as error:
            return error.code, None

    def payload(epoch, provider="Microsoft-Windows-Security-Auditing"):
        return {
            "protocol_version": 2,
            "device_id": device,
            "channel": "Security",
            "source_epoch": epoch,
            "events": [event(500, provider)],
        }

    try:
        first = payload("a" * 32)
        second = payload("b" * 32)
        assert post(first, "wrong-token")[0] == 401
        assert post({**first, "device_id": "spoofed"})[0] == 403
        expected = (200, {"accepted": True, "last_record_id": 500})
        assert post(first) == expected
        assert post(first) == expected
        assert post(second) == expected
        assert post(payload("a" * 32, "changed"))[0] == 400
        assert post(payload("invalid"))[0] == 400
        with db.cursor() as cursor:
            cursor.execute(
                "SELECT source_epoch, count(*) FROM windows_pilot.security_events_v2 "
                "WHERE device_id=%s GROUP BY source_epoch ORDER BY source_epoch",
                (device,),
            )
            assert [(row[0].strip(), row[1]) for row in cursor.fetchall()] == [("a" * 32, 1), ("b" * 32, 1)]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_epoch_rls_receiver_role_can_ingest_replay_and_read_only_its_device(db):
    """Use a real non-owner role: RLS must allow service writes and isolate reads."""
    from staging_postgres_epoch_receiver import accept_epoch_batch_postgres

    db.execute((Path(__file__).parent / "staging_postgres_epoch_schema.sql").read_text())
    device = "ci-" + uuid.uuid4().hex
    other = "ci-" + uuid.uuid4().hex
    batch = {"protocol_version": 2, "device_id": device, "channel": "Security", "source_epoch": "d" * 32, "events": [event(21)]}
    accept_epoch_batch_postgres(db, {**batch, "device_id": other})
    with psycopg.connect(os.environ["AEGIS_WINDOWS_TEST_DATABASE_URL"], autocommit=True) as conn:
        conn.execute("SET ROLE windows_security_receiver")
        assert accept_epoch_batch_postgres(conn, batch)["accepted"] is True
        assert accept_epoch_batch_postgres(conn, batch)["accepted"] is True
        # Transaction-local context must not leak across pooled requests.
        assert conn.execute("SELECT count(*) FROM windows_pilot.security_events_v2").fetchone()[0] == 0
        with conn.transaction():
            conn.execute("SELECT set_config('app.windows_device_id', %s, true)", (device,))
            assert conn.execute("SELECT DISTINCT device_id FROM windows_pilot.security_events_v2").fetchall() == [(device,)]
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                with conn.transaction():
                    conn.execute(
                        "INSERT INTO windows_pilot.security_events_v2 "
                        "SELECT device_id,channel,source_epoch,computer,record_id+1,event_id,event_json,received_at "
                        "FROM windows_pilot.security_events_v2 WHERE device_id=%s",
                        (device,),
                    )
                    conn.execute("DELETE FROM windows_pilot.security_events_v2")
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                with conn.transaction():
                    conn.execute(
                        "INSERT INTO windows_pilot.security_events_v2 "
                        "(device_id,channel,source_epoch,computer,record_id,event_id,event_json) "
                        "VALUES(%s,'Security',%s,'ci-host',22,4624,'{}')",
                        (other, "d" * 32),
                    )


def test_receiver_cannot_acknowledge_uncommitted_outer_transaction(db):
    from staging_postgres_epoch_receiver import accept_epoch_batch_postgres

    db.execute((Path(__file__).parent / "staging_postgres_epoch_schema.sql").read_text())
    batch = {
        "protocol_version": 2,
        "device_id": "ci-" + uuid.uuid4().hex,
        "channel": "Security",
        "source_epoch": "e" * 32,
        "events": [event(31)],
    }
    with db.transaction():
        with pytest.raises(RuntimeError, match="idle"):
            accept_epoch_batch_postgres(db, batch)


def test_concurrent_epoch_replays_commit_once(db):
    from concurrent.futures import ThreadPoolExecutor

    from staging_postgres_epoch_receiver import accept_epoch_batch_postgres

    db.execute((Path(__file__).parent / "staging_postgres_epoch_schema.sql").read_text())
    device = "ci-" + uuid.uuid4().hex
    batch = {"protocol_version": 2, "device_id": device, "channel": "Security", "source_epoch": "b" * 32, "events": [event(51), event(52)]}

    def receive(_):
        with psycopg.connect(os.environ["AEGIS_WINDOWS_TEST_DATABASE_URL"], autocommit=True) as connection:
            connection.execute("SET ROLE windows_security_receiver")
            return accept_epoch_batch_postgres(connection, batch)

    with ThreadPoolExecutor(max_workers=4) as workers:
        assert list(workers.map(receive, range(4))) == [{"accepted": True, "last_record_id": 52}] * 4
    assert db.execute("SELECT count(*) FROM windows_pilot.security_events_v2 WHERE device_id=%s", (device,)).fetchone()[0] == 2


def test_wsgi_real_http_receipts_auth_and_postgres(db, monkeypatch):
    """Exercise the deployable WSGI path through actual HTTP and PostgreSQL."""
    import json
    import threading
    import urllib.error
    import urllib.request
    from wsgiref.simple_server import WSGIRequestHandler, make_server

    from staging_epoch_wsgi import application

    class Quiet(WSGIRequestHandler):
        def log_message(self, *args):
            pass

    db.execute((Path(__file__).parent / "staging_postgres_epoch_schema.sql").read_text())
    device = "ci-" + uuid.uuid4().hex
    token = "ci-only-" + uuid.uuid4().hex
    monkeypatch.setenv("AEGIS_WINDOWS_DEVICE_ID", device)
    monkeypatch.setenv("AEGIS_WINDOWS_STAGING_TOKEN", token)
    from psycopg.conninfo import make_conninfo

    monkeypatch.setenv(
        "AEGIS_WINDOWS_STAGING_DATABASE_URL",
        make_conninfo(os.environ["AEGIS_WINDOWS_TEST_DATABASE_URL"], options="-c role=windows_security_receiver"),
    )
    server = make_server("127.0.0.1", 0, application, handler_class=Quiet)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    def request(route, payload=None, credential=token):
        req = urllib.request.Request(
            f"http://127.0.0.1:{server.server_port}{route}",
            data=json.dumps(payload).encode() if payload else None,
            headers={"Authorization": f"Bearer {credential}", "Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as response:
                return response.status, json.load(response)
        except urllib.error.HTTPError as exc:
            return exc.code, json.load(exc)

    try:
        route = "/v2/windows-security/status"
        assert request("/v2/health/ready") == (200, {"ready": True})
        assert request(route, credential="wrong")[0] == 401
        assert request(route)[1]["events_received"] == 0
        batch = {"protocol_version": 2, "device_id": device, "channel": "Security", "source_epoch": "f" * 32, "events": [event(41)]}
        ingest = "/v2/windows-security/events"
        assert request(ingest, {**batch, "device_id": "spoofed"})[0] == 403
        assert request(ingest, batch) == (200, {"accepted": True, "last_record_id": 41})
        assert request(ingest, batch)[0] == 200
        status = request(route)[1]
        assert status["events_received"] == 1
        assert status["last_received_at"] is not None
        assert status["scope"] == "staging_metadata"
        assert status["detection_pipeline"] == "not_connected"
        assert request(ingest, {**batch, "events": [event(41, "conflict")]})[0] == 400
        monkeypatch.setenv("AEGIS_WINDOWS_STAGING_DATABASE_URL", "postgresql://127.0.0.1:1/unavailable")
        assert request(route)[0] == 503
        assert request(ingest, batch)[0] == 503
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
