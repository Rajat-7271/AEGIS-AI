"""Broker-backed replay verification for the opt-in lake worker.

Requires a local Kafka-compatible broker at localhost:19092.
"""
import asyncio
import uuid

import pytest
from aiokafka import AIOKafkaProducer

from app.services.durable_lake_processor import DurableLakeProcessor
from app.services.lake_offsets import OffsetTracker
from app.workers.durable_lake_worker import DurableLakeWorker

pytestmark = pytest.mark.asyncio

BOOTSTRAP = "localhost:19092"


class RecordingSink:
    def __init__(self):
        self.events = []
        self.fail = False

    async def persist(self, event):
        if self.fail:
            raise OSError("simulated ClickHouse outage")
        self.events.append(event)


def worker_for(topic, group, sink):
    offsets = OffsetTracker()
    processor = DurableLakeProcessor(sink, offsets)

    return DurableLakeWorker(
        processor=processor,
        offsets=offsets,
        bootstrap_servers=BOOTSTRAP,
        topic=topic,
        group_id=group,
        existing_fusion_group="aegis-fusion",
        security_kwargs={},
    )


async def poll_until(worker, expected=1):
    for _ in range(40):
        result = await worker.poll_once()
        if result >= expected:
            return
    raise AssertionError("Timed out waiting for Kafka event")


@pytest.mark.timeout(90)
async def test_broker_commit_and_failed_event_replay():
    suffix = uuid.uuid4().hex[:12]
    topic = f"aegis-lake-integration-{suffix}"
    group = f"aegis-lake-integration-group-{suffix}"

    producer = AIOKafkaProducer(
        bootstrap_servers=BOOTSTRAP,
    )

    await producer.start()
    try:
        await producer.send_and_wait(topic, b'{"id":"first"}')
        await producer.send_and_wait(topic, b'{"id":"second"}')
    finally:
        await producer.stop()

    sink = RecordingSink()
    worker = worker_for(topic, group, sink)

    await worker.start()
    try:
        await poll_until(worker)
        assert sink.events == [{"id": "first"}]

        sink.fail = True

        with pytest.raises(OSError, match="ClickHouse outage"):
            await poll_until(worker)
    finally:
        await worker.stop()

    # A fresh consumer in the same group should replay the uncommitted
    # second event, not the already committed first event.
    recovered_sink = RecordingSink()
    recovered = worker_for(topic, group, recovered_sink)

    await recovered.start()
    try:
        await poll_until(recovered)
        assert recovered_sink.events == [{"id": "second"}]
    finally:
        await recovered.stop()
