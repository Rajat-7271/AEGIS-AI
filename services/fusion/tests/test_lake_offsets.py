"""Synthetic offset safety tests; no Kafka or ClickHouse connections."""
import pytest

from app.services.lake_offsets import OffsetTracker, PartitionProgress


def test_out_of_order_persistence_never_skips_gap() -> None:
    progress = PartitionProgress(next_offset=10, committed_next=10)
    assert progress.acknowledge_persisted(12) is None
    assert progress.acknowledge_persisted(10) == 11
    progress.mark_committed(11)
    assert progress.acknowledge_persisted(11) == 13
    progress.mark_committed(13)
    assert progress.committed_next == 13


def test_replay_and_failed_commit_do_not_advance_acknowledged_position() -> None:
    progress = PartitionProgress(next_offset=5, committed_next=5)
    assert progress.acknowledge_persisted(5) == 6
    assert progress.committed_next == 5  # Kafka commit not yet confirmed
    assert progress.acknowledge_persisted(5) == 6  # safe retry
    progress.mark_committed(6)
    assert progress.acknowledge_persisted(5) is None


def test_partitions_are_independent_and_rebalance_resets_state() -> None:
    tracker = OffsetTracker()
    tracker.assign("raw", 0, 5)
    tracker.assign("raw", 1, 100)
    assert tracker.persisted("raw", 0, 6) is None
    assert tracker.persisted("raw", 1, 100) == 101
    assert tracker.persisted("raw", 0, 5) == 7
    tracker.revoke("raw", 0)
    with pytest.raises(KeyError):
        tracker.persisted("raw", 0, 7)
    tracker.assign("raw", 0, 5)
    assert tracker.persisted("raw", 0, 5) == 6


def test_rejects_invalid_commit_and_regression() -> None:
    with pytest.raises(ValueError):
        PartitionProgress(next_offset=-1)
    progress = PartitionProgress(next_offset=3, committed_next=3)
    with pytest.raises(ValueError):
        progress.mark_committed(4)
    assert progress.acknowledge_persisted(3) == 4
    progress.mark_committed(4)
    with pytest.raises(ValueError):
        progress.mark_committed(3)
