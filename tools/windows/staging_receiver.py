"""Isolated staging Windows Security receiver core (stdlib only).

This is deliberately NOT mounted in the production API. A future authenticated
HTTPS route can call accept_batch after verifying the bearer credential.
"""
from __future__ import annotations

import hmac
import json
import sqlite3
from pathlib import Path

ALLOWED_IDS = {4624, 4625, 4672, 4688, 4720, 1102}
SYSTEM_FIELDS = {"EventID", "Channel", "Computer", "EventRecordID", "TimeCreated", "Provider"}
MAX_EVENTS = 100
MAX_REQUEST_BYTES = 260_096


class InvalidBatch(ValueError):
    pass


def authorize(provided: str, expected: str) -> None:
    if not expected or not provided or not hmac.compare_digest(provided, expected):
        raise PermissionError("Unauthorized device")


def validate(payload: object) -> tuple[str, list[dict]]:
    if not isinstance(payload, dict) or set(payload) != {"device_id", "events"}:
        raise InvalidBatch("Invalid request envelope")
    device = payload["device_id"]
    events = payload["events"]
    if not isinstance(device, str) or not 1 <= len(device) <= 128 or not all(c.isascii() and (c.isalnum() or c in "._-") for c in device):
        raise InvalidBatch("Invalid device identifier")
    if not isinstance(events, list) or not 1 <= len(events) <= MAX_EVENTS:
        raise InvalidBatch("Invalid batch size")
    previous = 0
    for event in events:
        if not isinstance(event, dict) or set(event) != {"System", "EventData"} or event["EventData"] != {}:
            raise InvalidBatch("Invalid event metadata")
        system = event["System"]
        if not isinstance(system, dict) or set(system) != SYSTEM_FIELDS:
            raise InvalidBatch("Invalid system fields")
        record = system["EventRecordID"]
        if type(record) is not int or record < 1 or record <= previous:
            raise InvalidBatch("Invalid event record ordering")
        if type(system["EventID"]) is not int or system["EventID"] not in ALLOWED_IDS or system["Channel"] != "Security":
            raise InvalidBatch("Unsupported Windows event")
        if any(not isinstance(system[k], str) or not system[k] or len(system[k]) > 512 for k in ("Computer", "TimeCreated", "Provider")):
            raise InvalidBatch("Invalid metadata value")
        previous = record
    return device, events


def accept_batch(database: Path, payload: object) -> dict:
    """Atomically persist all events; only then acknowledge final record ID.

    Idempotency scope is device+computer+channel+record ID. Log resets and
    reused record IDs require an explicit source epoch before production use.
    """
    device, events = validate(payload)
    database.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(database, timeout=10) as connection:
        connection.execute("PRAGMA busy_timeout=10000")
        connection.execute(
            """CREATE TABLE IF NOT EXISTS windows_security_events (
                device_id TEXT NOT NULL,
                computer TEXT NOT NULL,
                channel TEXT NOT NULL,
                record_id INTEGER NOT NULL,
                event_id INTEGER NOT NULL,
                event_json TEXT NOT NULL,
                PRIMARY KEY(device_id, computer, channel, record_id)
            )"""
        )
        with connection:
            for event in events:
                system = event["System"]
                serialized = json.dumps(event, sort_keys=True, separators=(",", ":"))
                key = (device, system["Computer"], system["Channel"], system["EventRecordID"])
                existing = connection.execute(
                    "SELECT event_json FROM windows_security_events WHERE device_id=? AND computer=? AND channel=? AND record_id=?",
                    key,
                ).fetchone()
                if existing:
                    if existing[0] != serialized:
                        raise InvalidBatch("Conflicting replay for existing event identity")
                    continue
                connection.execute(
                    """INSERT INTO windows_security_events
                    (device_id, computer, channel, record_id, event_id, event_json)
                    VALUES (?, ?, ?, ?, ?, ?)""",
                    (*key, system["EventID"], serialized),
                )
    return {"accepted": True, "last_record_id": events[-1]["System"]["EventRecordID"]}
