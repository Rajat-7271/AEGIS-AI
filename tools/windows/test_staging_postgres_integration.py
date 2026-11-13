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
