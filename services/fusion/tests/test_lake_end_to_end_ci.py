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


async def test_failed_lake_write_replays_after_consumer_restart():
    """An unacknowledged Kafka record survives a failed lake insert."""
    suffix = uuid.uuid4().hex[:12]
    topic = f"aegis-lake-recovery-{suffix}"
    group = f"aegis-lake-recovery-group-{suffix}"
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

    class FailingSink:
        async def persist(self, message):
            raise OSError("synthetic lake outage")

    def make_worker(sink):
        offsets = OffsetTracker()
        return DurableLakeWorker(
            processor=DurableLakeProcessor(sink, offsets),
            offsets=offsets, bootstrap_servers="localhost:19092",
            topic=topic, group_id=group, existing_fusion_group="aegis-fusion",
            security_kwargs={},
        )

    try:
        failed = make_worker(FailingSink())
        await failed.start()
        try:
            for _ in range(40):
                try:
                    await failed.poll_once()
                except OSError as exc:
                    assert "synthetic lake outage" in str(exc)
                    break
            else:
                pytest.fail("Expected synthetic ClickHouse write failure")
        finally:
            await failed.stop()

        recovered = make_worker(DurableLakeSink(db))
        await recovered.start()
        try:
            for _ in range(40):
                if await recovered.poll_once():
                    break
            else:
                pytest.fail("Uncommitted Kafka record was not replayed")
        finally:
            await recovered.stop()

        rows = db.execute(
            "SELECT count() FROM aisoc.raw_events FINAL "
            "WHERE tenant_id = %(tenant)s AND event_id = %(event)s",
            {"tenant": str(tenant), "event": str(event_id)},
        )
        assert rows[0][0] == 1
    finally:
        db.disconnect()


async def test_acknowledgement_lost_after_clickhouse_write_replays_idempotently():
    """Simulate server write success followed by a lost client acknowledgement."""
    suffix = uuid.uuid4().hex[:12]
    topic = f"aegis-lake-ambiguous-{suffix}"
    group = f"aegis-lake-ambiguous-group-{suffix}"
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
    real_sink = DurableLakeSink(db)

    class LostAcknowledgementSink:
        async def persist(self, message):
            await real_sink.persist(message)
            raise OSError("synthetic lost acknowledgement after successful write")

    def make_worker(sink):
        offsets = OffsetTracker()
        return DurableLakeWorker(
            processor=DurableLakeProcessor(sink, offsets),
            offsets=offsets, bootstrap_servers="localhost:19092",
            topic=topic, group_id=group, existing_fusion_group="aegis-fusion",
            security_kwargs={},
        )

    def count_rows():
        return db.execute(
            "SELECT count() FROM aisoc.raw_events FINAL "
            "WHERE tenant_id = %(tenant)s AND event_id = %(event)s",
            {"tenant": str(tenant), "event": str(event_id)},
        )[0][0]

    try:
        failed = make_worker(LostAcknowledgementSink())
        await failed.start()
        try:
            for _ in range(40):
                try:
                    await failed.poll_once()
                except OSError as exc:
                    assert "lost acknowledgement" in str(exc)
                    break
            else:
                pytest.fail("Expected synthetic lost acknowledgement")
        finally:
            await failed.stop()

        assert count_rows() == 1
        recovered = make_worker(real_sink)
        await recovered.start()
        try:
            for _ in range(40):
                if await recovered.poll_once():
                    break
            else:
                pytest.fail("Unacknowledged Kafka event was not replayed")
        finally:
            await recovered.stop()
        assert count_rows() == 1
    finally:
        db.disconnect()
