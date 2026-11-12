"""Offset accounting for a dedicated, durable event-lake Kafka consumer.

This module is deliberately independent of aiokafka and ClickHouse. It does
not change the existing fusion worker's offset-commit behavior.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class PartitionProgress:
    """Track contiguous persisted offsets within one topic-partition.

    Kafka commits the *next* offset, not the last processed offset. A gap must
    never be crossed even when later inserts finish before earlier ones.
    """

    next_offset: int
    persisted: set[int] = field(default_factory=set)
    committed_next: int | None = None

    def __post_init__(self) -> None:
        if self.next_offset < 0:
            raise ValueError("next_offset must be nonnegative")

    def acknowledge_persisted(self, offset: int) -> int | None:
        """Return the safe next-offset commit candidate, or None.

        The caller must commit the returned candidate to Kafka and only then
        call mark_committed. Repeating an acknowledgement is harmless.
        """
        if offset < self.next_offset:
            # Persistence succeeded, but the Kafka commit may have failed.
            # Retry the contiguous candidate until Kafka confirms it.
            if self.committed_next is None or self.next_offset > self.committed_next:
                return self.next_offset
            return None
        self.persisted.add(offset)
        while self.next_offset in self.persisted:
            self.persisted.remove(self.next_offset)
            self.next_offset += 1
        if self.committed_next is None or self.next_offset > self.committed_next:
            return self.next_offset
        return None

    def mark_committed(self, next_offset: int) -> None:
        """Record Kafka's successful acknowledgement, never a failed attempt."""
        if next_offset > self.next_offset or next_offset < 0:
            raise ValueError("cannot commit beyond contiguous persistence")
        if self.committed_next is not None and next_offset < self.committed_next:
            raise ValueError("commit regression")
        self.committed_next = next_offset


class OffsetTracker:
    """Partition-isolated progress; reset on assignment/rebalance."""

    def __init__(self) -> None:
        self._partitions: dict[tuple[str, int], PartitionProgress] = {}

    def assign(self, topic: str, partition: int, starting_offset: int) -> None:
        self._partitions[(topic, partition)] = PartitionProgress(
            next_offset=starting_offset, committed_next=starting_offset
        )

    def revoke(self, topic: str, partition: int) -> None:
        self._partitions.pop((topic, partition), None)

    def persisted(self, topic: str, partition: int, offset: int) -> int | None:
        return self._partitions[(topic, partition)].acknowledge_persisted(offset)

    def committed(self, topic: str, partition: int, next_offset: int) -> None:
        self._partitions[(topic, partition)].mark_committed(next_offset)
