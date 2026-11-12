"""Unit tests for durable lake partition lifecycle."""
from dataclasses import dataclass

import pytest

from app.services.lake_offsets import OffsetTracker
from app.services.lake_rebalance import LakeRebalanceListener

pytestmark = pytest.mark.asyncio


@dataclass(frozen=True)
class TP:
    topic: str = "raw-events"
    partition: int = 0


class Processor:
    def __init__(self):
        self.revoked = []

    async def revoke_partition(self, topic, partition):
        self.revoked.append((topic, partition))


class Consumer:
    async def position(self, tp):
        return 42


async def test_assignment_initializes_committed_position():
    offsets = OffsetTracker()
    listener = LakeRebalanceListener(
        processor=Processor(),
        offsets=offsets,
        consumer=Consumer(),
    )

    await listener.on_partitions_assigned({TP()})

    progress = offsets._partitions[("raw-events", 0)]
    assert progress.next_offset == 42
    assert progress.committed_next == 42


async def test_revocation_drains_processing():
    offsets = OffsetTracker()
    processor = Processor()
    listener = LakeRebalanceListener(
        processor=processor,
        offsets=offsets,
        consumer=Consumer(),
    )

    await listener.on_partitions_revoked({TP()})

    assert processor.revoked == [("raw-events", 0)]
