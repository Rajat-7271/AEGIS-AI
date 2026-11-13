"""Offline transactional PostgreSQL adapter contract tests; no database needed."""
import importlib.util
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT))
spec = importlib.util.spec_from_file_location("pg_receiver", ROOT / "staging_postgres_receiver.py")
receiver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(receiver)


def event(record):
    return {"System": {
        "EventID": 4624, "Channel": "Security", "Computer": "test",
        "EventRecordID": record, "TimeCreated": "2026-11-13T00:00:00Z",
        "Provider": "Microsoft-Windows-Security-Auditing",
    }, "EventData": {}}


class Transaction:
    def __init__(self, db):
        self.db = db

    def __enter__(self):
        self.snapshot = dict(self.db.rows)
        return self

    def __exit__(self, typ, value, traceback):
        if typ is not None:
            self.db.rows = self.snapshot
        return False


class Cursor:
    def __init__(self, db):
        self.db = db
        self.result = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def execute(self, sql, params):
        if sql == receiver.INSERT_SQL:
            key = tuple(params[:4])
            if key not in self.db.rows:
                import json
                self.db.rows[key] = json.loads(params[5])
                self.result = (params[3],)
            else:
                self.result = None
        elif sql == receiver.LOOKUP_SQL:
            self.result = (self.db.rows[tuple(params)],) if tuple(params) in self.db.rows else None
        else:
            raise AssertionError("Unexpected SQL")

    def fetchone(self):
        return self.result


class Database:
    def __init__(self):
        self.rows = {}

    def transaction(self):
        return Transaction(self)

    def cursor(self):
        return Cursor(self)


def test_commit_and_idempotent_replay():
    db = Database()
    payload = {"device_id": "test-device", "events": [event(1), event(2)]}
    expected = {"accepted": True, "last_record_id": 2}
    assert receiver.accept_batch_postgres(db, payload) == expected
    assert receiver.accept_batch_postgres(db, payload) == expected
    assert len(db.rows) == 2


def test_conflicting_replay_rolls_back_new_rows():
    db = Database()
    receiver.accept_batch_postgres(db, {"device_id": "test-device", "events": [event(2)]})
    changed = event(2)
    changed["System"]["Provider"] = "OtherProvider"
    with pytest.raises(receiver.InvalidBatch, match="Conflicting replay"):
        receiver.accept_batch_postgres(db, {"device_id": "test-device", "events": [event(1), changed]})
    assert len(db.rows) == 1
    assert next(iter(db.rows))[3] == 2


def test_invalid_metadata_rejected_before_database_transaction():
    db = Database()
    bad = event(1)
    bad["EventData"] = {"private": "data"}
    with pytest.raises(receiver.InvalidBatch):
        receiver.accept_batch_postgres(db, {"device_id": "test-device", "events": [bad]})
    assert db.rows == {}
