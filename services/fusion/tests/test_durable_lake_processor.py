"""Isolated Kafka-commit tests; no Kafka broker or ClickHouse required."""
from __future__ import annotations

from dataclasses import dataclass

import pytest

from app.services.durable_lake_processor import DurableLakeProcessor
from app.services.durable_lake_sink import LakePersistenceError
from app.services.lake_offsets import OffsetTracker

pytestmark = pytest.mark.asyncio


@dataclass(frozen=True)
class _TP:
    topic: str = "raw-events"
    partition: int = 0


class _Sink:
    def __init__(self):
        self.fail = False
        self.persisted = []

    async def persist(self, event):
        if self.fail:
            raise LakePersistenceError("write failed")
        self.persisted.append(event)


class _Consumer:
    def __init__(self):
        self.fail = False
        self.commits = []

    async def commit(self, offsets):
        self.commits.append(offsets)
        if self.fail:
            raise OSError("commit failed")


def _setup():
    offsets = OffsetTracker()
    offsets.assign("raw-events", 0, 10)
    sink, consumer = _Sink(), _Consumer()
    return DurableLakeProcessor(sink, offsets), sink, consumer, offsets


async def test_persist_before_partition_specific_commit():
    processor, sink, consumer, offsets = _setup()
    await processor.process(consumer=consumer, topic_partition=_TP(), offset=10, message={"id": "a"})
    assert sink.persisted == [{"id": "a"}]
    assert consumer.commits == [{_TP(): 11}]
    assert offsets._partitions[("raw-events", 0)].committed_next == 11


async def test_failed_insert_never_commits():
    processor, sink, consumer, offsets = _setup()
    sink.fail = True
    with pytest.raises(LakePersistenceError):
        await processor.process(consumer=consumer, topic_partition=_TP(), offset=10, message={})
    assert consumer.commits == []
    assert offsets._partitions[("raw-events", 0)].next_offset == 10


async def test_failed_commit_can_be_retried_without_skipping():
    processor, sink, consumer, offsets = _setup()
    consumer.fail = True
    with pytest.raises(OSError, match="commit failed"):
        await processor.process(consumer=consumer, topic_partition=_TP(), offset=10, message={"id": "a"})
    assert offsets._partitions[("raw-events", 0)].committed_next == 10
    consumer.fail = False
    await processor.process(consumer=consumer, topic_partition=_TP(), offset=10, message={"id": "a"})
    assert consumer.commits[-1] == {_TP(): 11}
    assert offsets._partitions[("raw-events", 0)].committed_next == 11


async def test_out_of_order_completion_does_not_cross_gap():
    processor, sink, consumer, offsets = _setup()
    await processor.process(consumer=consumer, topic_partition=_TP(), offset=11, message={"id": "b"})
    assert consumer.commits == []
    await processor.process(consumer=consumer, topic_partition=_TP(), offset=10, message={"id": "a"})
    assert consumer.commits == [{_TP(): 12}]


async def test_reassignment_during_persist_does_not_commit_stale_offset():
    processor, sink, consumer, offsets = _setup()

    async def persist_and_reassign(event):
        offsets.revoke("raw-events", 0)
        offsets.assign("raw-events", 0, 10)

    sink.persist = persist_and_reassign
    await processor.process(
        consumer=consumer, topic_partition=_TP(), offset=10, message={"id": "old"}
    )
    assert consumer.commits == []
    assert offsets._partitions[("raw-events", 0)].next_offset == 10
    assert offsets._partitions[("raw-events", 0)].committed_next == 10
