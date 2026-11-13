"""Experimental v2 epoch-aware PostgreSQL receiver; not mounted in production."""

from __future__ import annotations

import json
from typing import Any

from source_epoch_contract import validate_epoch_batch
from staging_receiver import InvalidBatch

INSERT_SQL = """
INSERT INTO windows_pilot.security_events_v2
    (device_id, channel, source_epoch, computer, record_id, event_id, event_json)
VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb)
ON CONFLICT (device_id, channel, source_epoch, computer, record_id) DO NOTHING
RETURNING record_id
"""

LOOKUP_SQL = """
SELECT event_json FROM windows_pilot.security_events_v2
WHERE device_id=%s AND channel=%s AND source_epoch=%s
  AND computer=%s AND record_id=%s
"""


def accept_epoch_batch_postgres(connection: Any, payload: object) -> dict:
    """Commit an entire v2 batch before acknowledging its last record."""
    (device, channel, epoch), events = validate_epoch_batch(payload)
    # A savepoint inside a caller-owned transaction is not durable acceptance.
    if connection.info.transaction_status != 0:
        raise RuntimeError("Receiver requires an idle database connection")
    with connection.transaction():
        with connection.cursor() as cursor:
            cursor.execute("SELECT set_config('app.windows_device_id', %s, true)", (device,))
            for event in events:
                system = event["System"]
                key = (device, channel, epoch, system["Computer"], system["EventRecordID"])
                serialized = json.dumps(event, sort_keys=True, separators=(",", ":"))
                cursor.execute(INSERT_SQL, (*key, system["EventID"], serialized))
                if cursor.fetchone() is not None:
                    continue
                cursor.execute(LOOKUP_SQL, key)
                existing = cursor.fetchone()
                if existing is None:
                    raise RuntimeError("Replay row disappeared during transaction")
                old = existing[0]
                if isinstance(old, str):
                    old = json.loads(old)
                if old != event:
                    raise InvalidBatch("Conflicting replay for existing event identity")
    return {"accepted": True, "last_record_id": events[-1]["System"]["EventRecordID"]}
