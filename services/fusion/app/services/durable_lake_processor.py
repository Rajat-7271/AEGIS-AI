"""Single-record durable lake processing, independent of the live fusion worker.

A dedicated Kafka consumer can use this boundary to persist one record and
commit only its contiguous, acknowledged offset. The caller owns Kafka
assignment/rebalance fencing and must not share the fusion consumer group.
"""
from __future__ import annotations

import asyncio
from typing import Any

from app.services.durable_lake_sink import DurableLakeSink
from app.services.lake_offsets import OffsetTracker


class DurableLakeProcessor:
    """Coordinate a durable insert with a per-partition Kafka commit."""

    def __init__(self, sink: DurableLakeSink, offsets: OffsetTracker) -> None:
        self._sink = sink
        self._offsets = offsets
        self._partition_locks: dict[tuple[str, int], asyncio.Lock] = {}

    async def revoke_partition(self, topic: str, partition: int) -> None:
        """Drain in-flight processing before revoking partition ownership.

        The Kafka consumer must stop dispatching new records for this
        partition before awaiting this method.
        """
        key = (topic, partition)
        lock = self._partition_locks.setdefault(key, asyncio.Lock())
        async with lock:
            self._offsets.revoke(topic, partition)

    async def process(
        self,
        *,
        consumer: Any,
        topic_partition: Any,
        offset: int,
        message: dict,
    ) -> None:
        key = (topic_partition.topic, topic_partition.partition)
        lock = self._partition_locks.setdefault(key, asyncio.Lock())

        async with lock:
            assignment = self._offsets._partitions.get(key)
            if assignment is None:
                return

            await self._sink.persist(message)

            if self._offsets._partitions.get(key) is not assignment:
                return

            next_offset = self._offsets.persisted(
                topic_partition.topic, topic_partition.partition, offset
            )
            if next_offset is None:
                return

            await consumer.commit({topic_partition: next_offset})

            if self._offsets._partitions.get(key) is assignment:
                self._offsets.committed(
                    topic_partition.topic, topic_partition.partition, next_offset
                )
