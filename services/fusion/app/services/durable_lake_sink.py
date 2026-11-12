"""Durable lake insert boundary for a future dedicated Kafka consumer.

Unlike the existing best-effort LakeWriter, this adapter never acknowledges
an event until ClickHouse's INSERT call returns successfully. It does not
manage Kafka subscriptions or offsets; those belong to the caller.
"""
from __future__ import annotations

import asyncio
from datetime import datetime
from typing import Any

from app.services.lake_writer import _INSERT_SQL, _to_ip_obj, event_to_row


class LakePersistenceError(RuntimeError):
    """The caller must retry the event and must not commit its Kafka offset."""


class DurableLakeSink:
    """A synchronous-acknowledged, single-event lake insert boundary.

    One event per insert is deliberately conservative: batching and ambiguous
    timeout deduplication require separate integration tests before rollout.
    """

    def __init__(self, client: Any) -> None:
        self._client = client

    async def persist(self, message: dict[str, Any]) -> None:
        # ReplacingMergeTree's deduplication key includes event_time. The
        # best-effort mapper falls back to now() on malformed timestamps,
        # which would turn a replay into a different key. Fail closed here.
        ocsf = message.get("ocsf_event") if isinstance(message, dict) else None
        raw_time = ocsf.get("time") if isinstance(ocsf, dict) else None
        if not isinstance(raw_time, str) or not raw_time.strip():
            raise LakePersistenceError("durable event requires a stable timestamp")
        try:
            parsed = datetime.fromisoformat(raw_time.replace("Z", "+00:00"))
        except ValueError as exc:
            raise LakePersistenceError("durable event requires a valid timestamp") from exc
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise LakePersistenceError("durable event timestamp must include timezone")

        row = event_to_row(message)
        if row is None or row["event_id"] is None:
            raise LakePersistenceError("raw event must have a valid tenant and deterministic UUID")
        if self._client is None:
            raise LakePersistenceError("ClickHouse client is unavailable")

        out = dict(row)
        out["source_ip"] = _to_ip_obj(row["source_ip"])
        out["dest_ip"] = _to_ip_obj(row["dest_ip"])
        try:
            await asyncio.to_thread(self._client.execute, _INSERT_SQL, [out], types_check=True)
        except Exception as exc:
            # An exception may follow a successful server-side write; the
            # caller must replay the SAME UUID, never synthesize a new one.
            raise LakePersistenceError("ClickHouse insert not acknowledged") from exc
