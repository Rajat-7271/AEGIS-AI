"""Reject malformed durable-lake records without acknowledging Kafka offsets."""
import uuid
from dataclasses import dataclass

import pytest

from app.services.durable_lake_processor import DurableLakeProcessor
from app.services.durable_lake_sink import DurableLakeSink, LakePersistenceError
from app.services.lake_offsets import OffsetTracker

pytestmark = pytest.mark.asyncio


@dataclass(frozen=True)
class TP:
    topic: str = "raw-events"
    partition: int = 0


class Consumer:
    def __init__(self):
        self.commits = []

    async def commit(self, offsets):
        self.commits.append(offsets)


@pytest.mark.parametrize(
    "message",
    [
        {"id": "not-a-uuid", "tenant_id": str(uuid.uuid4()), "ocsf_event": {}},
        {"id": str(uuid.uuid4()), "tenant_id": "not-a-uuid", "ocsf_event": {}},
        {"id": str(uuid.uuid4()), "tenant_id": str(uuid.uuid4())},
        {"id": str(uuid.uuid4()), "tenant_id": str(uuid.uuid4()), "ocsf_event": None},
    ],
    ids=["invalid-event-id", "invalid-tenant-id", "missing-ocsf", "null-ocsf"],
)
async def test_malformed_event_never_commits(message):
    offsets = OffsetTracker()
    offsets.assign("raw-events", 0, 10)
    consumer = Consumer()
    processor = DurableLakeProcessor(DurableLakeSink(None), offsets)

    with pytest.raises(LakePersistenceError):
        await processor.process(
            consumer=consumer, topic_partition=TP(), offset=10, message=message
        )

    assert consumer.commits == []
    progress = offsets._partitions[("raw-events", 0)]
    assert progress.next_offset == 10
    assert progress.committed_next == 10
