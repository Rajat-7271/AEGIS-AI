"""Real ClickHouse integration tests. Requires localhost:19000."""
import asyncio
import uuid
from datetime import datetime, timezone

import pytest
from clickhouse_driver import Client

from app.services.durable_lake_sink import (
    DurableLakeSink,
    LakePersistenceError,
)
from app.services.durable_lake_processor import DurableLakeProcessor
from app.services.lake_offsets import OffsetTracker

HOST = "127.0.0.1"
PORT = 19000


def client():
    return Client(
        host=HOST,
        port=PORT,
        database="aisoc",
        user="default",
        connect_timeout=5,
        send_receive_timeout=10,
    )


def event(tenant, event_id, connector="windows-security"):
    return {
        "id": str(event_id),
        "tenant_id": str(tenant),
        "connector_type": connector,
        "ocsf_event": {
            "class_uid": 3002,
            "category_uid": 3,
            "severity_id": 2,
            "severity": "Informational",
            "activity_id": 1,
            "time": datetime.now(timezone.utc).isoformat(),
            "metadata": {
                "product": {"name": connector}
            },
            "device": {"name": "AEGIS-SYNTHETIC-HOST"},
            "process": {"name": "synthetic-test.exe"},
            "raw_data": "AEGIS synthetic validation event",
        },
    }


@pytest.mark.asyncio
async def test_real_clickhouse_insert_tenant_scope_and_replay():
    db = client()
    tenant_a = uuid.uuid4()
    tenant_b = uuid.uuid4()
    event_id = uuid.uuid4()

    sink = DurableLakeSink(db)

    try:
        first = event(tenant_a, event_id)
        await sink.persist(first)

        rows = db.execute(
            """
            SELECT tenant_id, event_id, connector_type
            FROM aisoc.raw_events FINAL
            WHERE tenant_id = %(tenant)s
              AND event_id = %(event)s
            """,
            {"tenant": str(tenant_a), "event": str(event_id)},
        )

        assert len(rows) == 1
        assert str(rows[0][0]) == str(tenant_a)
        assert str(rows[0][1]) == str(event_id)
        assert rows[0][2] == "windows-security"

        # Replay the same logical event, preserving its timestamp and UUID.
        await sink.persist(first)

        deduplicated = db.execute(
            """
            SELECT count()
            FROM aisoc.raw_events FINAL
            WHERE tenant_id = %(tenant)s
              AND event_id = %(event)s
            """,
            {"tenant": str(tenant_a), "event": str(event_id)},
        )

        assert deduplicated[0][0] == 1

        # The same event ID in another tenant must remain independently scoped.
        await sink.persist(event(tenant_b, event_id, "sysmon"))

        scoped = db.execute(
            """
            SELECT tenant_id, connector_type
            FROM aisoc.raw_events FINAL
            WHERE event_id = %(event)s
            ORDER BY tenant_id
            """,
            {"event": str(event_id)},
        )

        assert len(scoped) == 2
        assert {str(row[0]) for row in scoped} == {
            str(tenant_a),
            str(tenant_b),
        }
    finally:
        db.disconnect()


@pytest.mark.asyncio
async def test_real_clickhouse_processor_commits_after_write():
    db = client()
    tenant = uuid.uuid4()
    event_id = uuid.uuid4()
    offsets = OffsetTracker()
    offsets.assign("synthetic-events", 0, 7)

    class TP:
        topic = "synthetic-events"
        partition = 0

        def __hash__(self):
            return hash((self.topic, self.partition))

        def __eq__(self, other):
            return (
                getattr(other, "topic", None) == self.topic
                and getattr(other, "partition", None) == self.partition
            )

    class Consumer:
        def __init__(self):
            self.commits = []

        async def commit(self, mapping):
            self.commits.append(mapping)

    consumer = Consumer()
    processor = DurableLakeProcessor(DurableLakeSink(db), offsets)

    try:
        await processor.process(
            consumer=consumer,
            topic_partition=TP(),
            offset=7,
            message=event(tenant, event_id),
        )

        assert consumer.commits == [{TP(): 8}]

        count = db.execute(
            """
            SELECT count()
            FROM aisoc.raw_events FINAL
            WHERE tenant_id = %(tenant)s
              AND event_id = %(event)s
            """,
            {"tenant": str(tenant), "event": str(event_id)},
        )[0][0]

        assert count == 1
    finally:
        db.disconnect()


@pytest.mark.asyncio
async def test_real_clickhouse_unavailable_never_commits():
    db = client()
    db.disconnect()

    # A missing client must fail closed before any Kafka acknowledgement.
    offsets = OffsetTracker()
    offsets.assign("synthetic-events", 0, 10)

    class TP:
        topic = "synthetic-events"
        partition = 0

    class Consumer:
        def __init__(self):
            self.commits = []

        async def commit(self, mapping):
            self.commits.append(mapping)

    consumer = Consumer()
    processor = DurableLakeProcessor(DurableLakeSink(None), offsets)

    with pytest.raises(LakePersistenceError):
        await processor.process(
            consumer=consumer,
            topic_partition=TP(),
            offset=10,
            message=event(uuid.uuid4(), uuid.uuid4()),
        )

    assert consumer.commits == []
    assert offsets._partitions[("synthetic-events", 0)].next_offset == 10
