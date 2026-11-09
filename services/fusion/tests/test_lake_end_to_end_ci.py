"""Isolated Kafka -> durable worker -> real ClickHouse contract test."""
import json
import uuid

import pytest
from aiokafka import AIOKafkaProducer
from clickhouse_driver import Client

from app.services.durable_lake_processor import DurableLakeProcessor
from app.services.durable_lake_sink import DurableLakeSink
from app.services.lake_offsets import OffsetTracker
from app.workers.durable_lake_worker import DurableLakeWorker

pytestmark = pytest.mark.asyncio


async def test_kafka_to_clickhouse_and_restart_without_duplicate():
    suffix = uuid.uuid4().hex[:12]
    topic = f"aegis-lake-e2e-{suffix}"
    group = f"aegis-lake-e2e-group-{suffix}"
    tenant, event_id = uuid.uuid4(), uuid.uuid4()
    event = {
        "id": str(event_id), "tenant_id": str(tenant),
        "connector_type": "windows-security",
        "ocsf_event": {
            "class_uid": 3002, "category_uid": 3,
            "severity_id": 2, "severity": "Informational",
            "activity_id": 1, "time": "2026-11-09T00:00:00Z",
            "metadata": {"product": {"name": "windows-security"}},
        },
    }
    producer = AIOKafkaProducer(bootstrap_servers="localhost:19092")
    await producer.start()
    try:
        await producer.send_and_wait(topic, json.dumps(event).encode())
    finally:
        await producer.stop()

    db = Client(host="127.0.0.1", port=19000, database="aisoc")
    def worker():
        offsets = OffsetTracker()
        return DurableLakeWorker(
            processor=DurableLakeProcessor(DurableLakeSink(db), offsets),
            offsets=offsets, bootstrap_servers="localhost:19092",
            topic=topic, group_id=group, existing_fusion_group="aegis-fusion",
            security_kwargs={},
        )
    first = worker()
    try:
        await first.start()
        try:
            for _ in range(40):
                if await first.poll_once():
                    break
            else:
                pytest.fail("Kafka event was not processed")
        finally:
            await first.stop()
        rows = db.execute(
            "SELECT event_id FROM aisoc.raw_events FINAL "
            "WHERE tenant_id = %(tenant)s AND event_id = %(event)s",
            {"tenant": str(tenant), "event": str(event_id)},
        )
        assert len(rows) == 1

        restarted = worker()
        await restarted.start()
        try:
            assert await restarted.poll_once() == 0
        finally:
            await restarted.stop()
        rows = db.execute(
            "SELECT count() FROM aisoc.raw_events FINAL "
            "WHERE tenant_id = %(tenant)s AND event_id = %(event)s",
            {"tenant": str(tenant), "event": str(event_id)},
        )
        assert rows[0][0] == 1
    finally:
        db.disconnect()
