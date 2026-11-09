"""Partition ownership lifecycle for the dedicated durable lake consumer.

This module does not connect to Kafka or start background tasks.
"""
from __future__ import annotations

from aiokafka import ConsumerRebalanceListener

from app.services.durable_lake_processor import DurableLakeProcessor
from app.services.lake_offsets import OffsetTracker


class LakeRebalanceListener(ConsumerRebalanceListener):
    """Coordinate assignment changes with in-flight lake processing."""

    def __init__(
        self,
        *,
        processor: DurableLakeProcessor,
        offsets: OffsetTracker,
        consumer,
    ) -> None:
        self._processor = processor
        self._offsets = offsets
        self._consumer = consumer

    async def on_partitions_revoked(self, revoked) -> None:
        # The worker must stop dispatching records before revocation.
        for tp in revoked:
            await self._processor.revoke_partition(
                tp.topic, tp.partition
            )

    async def on_partitions_assigned(self, assigned) -> None:
        for tp in assigned:
            # The committed position is the starting point for replay.
            # The worker must ensure a valid position before processing.
            position = await self._consumer.position(tp)
            self._offsets.assign(tp.topic, tp.partition, position)
