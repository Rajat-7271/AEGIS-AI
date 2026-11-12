"""Regression tests for concurrent lake processing and Kafka rebalances."""
import asyncio
from dataclasses import dataclass

import pytest

from app.services.durable_lake_processor import DurableLakeProcessor
from app.services.lake_offsets import OffsetTracker

pytestmark = pytest.mark.asyncio


@dataclass(frozen=True)
class TP:
    topic: str = "raw-events"
    partition: int = 0


class ControlledSink:
    def __init__(self):
        self.started = asyncio.Event()
        self.release = asyncio.Event()
        self.persisted = []

    async def persist(self, message):
        self.started.set()
        await self.release.wait()
        self.persisted.append(message)


class ControlledConsumer:
    def __init__(self):
        self.commits = []
        self.started = asyncio.Event()
        self.release = asyncio.Event()
        self.block = False

    async def commit(self, offsets):
        self.started.set()
        if self.block:
            await self.release.wait()
        self.commits.append(offsets)


def setup():
    offsets = OffsetTracker()
    offsets.assign("raw-events", 0, 10)
    sink = ControlledSink()
    consumer = ControlledConsumer()
    processor = DurableLakeProcessor(sink, offsets)
    return processor, sink, consumer, offsets


async def test_revoke_during_persistence_prevents_commit():
    processor, sink, consumer, offsets = setup()

    task = asyncio.create_task(
        processor.process(
            consumer=consumer,
            topic_partition=TP(),
            offset=10,
            message={"id": "old"},
        )
    )

    await asyncio.wait_for(sink.started.wait(), 2)
    offsets.revoke("raw-events", 0)
    sink.release.set()

    await asyncio.wait_for(task, 2)

    assert consumer.commits == []
    assert ("raw-events", 0) not in offsets._partitions


async def test_reassignment_during_commit_does_not_update_new_assignment():
    processor, sink, consumer, offsets = setup()
    sink.release.set()
    consumer.block = True

    task = asyncio.create_task(
        processor.process(
            consumer=consumer,
            topic_partition=TP(),
            offset=10,
            message={"id": "old"},
        )
    )

    await asyncio.wait_for(consumer.started.wait(), 2)

    offsets.revoke("raw-events", 0)
    offsets.assign("raw-events", 0, 10)

    consumer.release.set()
    await asyncio.wait_for(task, 2)

    progress = offsets._partitions[("raw-events", 0)]
    assert progress.committed_next == 10


async def test_out_of_order_concurrent_persistence_commits_contiguous_offsets():
    processor, sink, consumer, offsets = setup()
    sink.release.set()

    await asyncio.gather(
        processor.process(
            consumer=consumer,
            topic_partition=TP(),
            offset=11,
            message={"id": "second"},
        ),
        processor.process(
            consumer=consumer,
            topic_partition=TP(),
            offset=10,
            message={"id": "first"},
        ),
    )

    assert offsets._partitions[("raw-events", 0)].next_offset == 12
    assert offsets._partitions[("raw-events", 0)].committed_next == 12
    assert consumer.commits[-1] == {TP(): 12}


async def test_revoke_waits_for_inflight_commit():
    processor, sink, consumer, offsets = setup()
    sink.release.set()
    consumer.block = True

    processing = asyncio.create_task(
        processor.process(
            consumer=consumer,
            topic_partition=TP(),
            offset=10,
            message={"id": "inflight"},
        )
    )

    await asyncio.wait_for(consumer.started.wait(), 2)

    revocation = asyncio.create_task(
        processor.revoke_partition("raw-events", 0)
    )

    # Revocation must not complete while Kafka commit is in progress.
    await asyncio.sleep(0)
    assert not revocation.done()

    consumer.release.set()
    await asyncio.wait_for(processing, 2)
    await asyncio.wait_for(revocation, 2)

    assert consumer.commits == [{TP(): 11}]
    assert ("raw-events", 0) not in offsets._partitions
