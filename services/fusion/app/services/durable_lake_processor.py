"""Single-record durable lake processing, independent of the live fusion worker.

A dedicated Kafka consumer can use this boundary to persist one record and
commit only its contiguous, acknowledged offset. The caller owns Kafka
assignment/rebalance fencing and must not share the fusion consumer group.
"""
from __future__ import annotations

from typing import Any

from app.services.durable_lake_sink import DurableLakeSink
from app.services.lake_offsets import OffsetTracker


class DurableLakeProcessor:
    """Coordinate a durable insert with a per-partition Kafka commit."""

    def __init__(self, sink: DurableLakeSink, offsets: OffsetTracker) -> None:
        self._sink = sink
        self._offsets = offsets

    async def process(
        self,
        *,
        consumer: Any,
        topic_partition: Any,
        offset: int,
        message: dict,
    ) -> None:
        # Capture assignment identity before the first asynchronous boundary.
        # A revoke/reassign replaces the progress object, even if the new
        # assignment starts at the same offset.
        key = (topic_partition.topic, topic_partition.partition)
        assignment = self._offsets._partitions[key]
        # If persistence fails, neither the offset tracker nor Kafka moves.
        await self._sink.persist(message)
        if self._offsets._partitions.get(key) is not assignment:
            return
        next_offset = self._offsets.persisted(
            topic_partition.topic, topic_partition.partition, offset
        )
        if next_offset is None:
            return

        # aiokafka commit() accepts a mapping from TopicPartition to the
        # NEXT offset. Never commit the consumer's entire assignment.
        await consumer.commit({topic_partition: next_offset})
        # Record acknowledgement only after Kafka confirms the commit.
        if self._offsets._partitions.get(key) is assignment:
            self._offsets.committed(
                topic_partition.topic, topic_partition.partition, next_offset
            )
