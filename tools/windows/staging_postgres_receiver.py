"""Optional PostgreSQL persistence for an isolated Windows Security staging service.

Requires psycopg 3 installed in the *staging service* environment.
Not imported by or mounted in the production API. No database connection
occurs on import. Credentials are supplied by the deployment environment.
"""
from __future__ import annotations

import json
from typing import Any

from staging_receiver import InvalidBatch, validate

INSERT_SQL = """
INSERT INTO windows_pilot.security_events
    (device_id, computer, channel, record_id, event_id, event_json)
VALUES (%s, %s, %s, %s, %s, %s::jsonb)
ON CONFLICT (device_id, computer, channel, record_id) DO NOTHING
RETURNING record_id
"""
LOOKUP_SQL = """
SELECT event_json FROM windows_pilot.security_events
WHERE device_id=%s AND computer=%s AND channel=%s AND record_id=%s
"""


def accept_batch_postgres(connection: Any, payload: object) -> dict:
    """Commit the whole validated batch before returning its acknowledgement.

    The caller owns the connection and must not reuse it with an open
    transaction. A database exception propagates and no ACK is produced.
    """
    device, events = validate(payload)
    with connection.transaction():
        with connection.cursor() as cursor:
            for event in events:
                system = event["System"]
                key = (device, system["Computer"], system["Channel"], system["EventRecordID"])
                serialized = json.dumps(event, sort_keys=True, separators=(",", ":"))
                cursor.execute(INSERT_SQL, (*key, system["EventID"], serialized))
                inserted = cursor.fetchone()
                if inserted is not None:
                    continue
                cursor.execute(LOOKUP_SQL, key)
                existing = cursor.fetchone()
                if existing is None:
                    raise RuntimeError("Replay row disappeared during transaction")
                existing_json = existing[0]
                if isinstance(existing_json, str):
                    existing_json = json.loads(existing_json)
                if existing_json != event:
                    raise InvalidBatch("Conflicting replay for existing event identity")
    return {"accepted": True, "last_record_id": events[-1]["System"]["EventRecordID"]}
