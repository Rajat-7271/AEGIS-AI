"""Offline tests for the dedicated durable lake Kafka worker."""
from dataclasses import dataclass

import pytest

from app.services.lake_offsets import OffsetTracker
from app.workers.durable_lake_worker import DurableLakeWorker

pytestmark = pytest.mark.asyncio


@dataclass(frozen=True)
class TP:
    topic: str = "raw-events"
    partition: int = 0


@dataclass
class Record:
    offset: int
    value: dict


class FakeConsumer:
    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.listener = None
        self.started = False
        self.stopped = False
        self.batches = {}

    def subscribe(self, *, topics, listener):
        self.topics = topics
        self.listener = listener

    async def start(self):
        self.started = True

    async def stop(self):
        self.stopped = True

    async def position(self, tp):
        return 10

    async def getmany(self, **kwargs):
        result = self.batches
        self.batches = {}
        return result


class Processor:
    def __init__(self, fail=False):
        self.calls = []
        self.fail = fail

    async def process(self, **kwargs):
        self.calls.append(kwargs)
        if self.fail:
            raise OSError("simulated persistence failure")

    async def revoke_partition(self, topic, partition):
        pass


def make_worker(processor=None, group="aegis-lake-test"):
    offsets = OffsetTracker()
    processor = processor or Processor()
    worker = DurableLakeWorker(
        processor=processor,
        offsets=offsets,
        bootstrap_servers="localhost:9092",
        topic="raw-events",
        group_id=group,
        existing_fusion_group="aegis-fusion",
        consumer_factory=FakeConsumer,
        security_kwargs={},
    )
    return worker, processor, offsets


async def test_rejects_shared_consumer_group():
    with pytest.raises(ValueError, match="separate Kafka group"):
        make_worker(group="aegis-fusion")


async def test_manual_commits_and_single_record_polling():
    worker, processor, offsets = make_worker()
    consumer = worker._consumer

    assert consumer.kwargs["enable_auto_commit"] is False
    assert consumer.topics == ["raw-events"]

    await worker.start()
    await consumer.listener.on_partitions_assigned({TP()})

    consumer.batches = {TP(): [Record(10, {"id": "a"})]}
    assert await worker.poll_once() == 1

    assert len(processor.calls) == 1
    assert processor.calls[0]["offset"] == 10

    await worker.stop()
    assert consumer.stopped


async def test_unassigned_partition_is_not_dispatched():
    worker, processor, offsets = make_worker()
    await worker.start()

    worker._consumer.batches = {
        TP(): [Record(10, {"id": "unassigned"})]
    }
    assert await worker.poll_once() == 0
    assert processor.calls == []

    await worker.stop()


async def test_persistence_failure_propagates():
    processor = Processor(fail=True)
    worker, _, offsets = make_worker(processor)

    await worker.start()
    await worker._consumer.listener.on_partitions_assigned({TP()})

    worker._consumer.batches = {
        TP(): [Record(10, {"id": "failure"})]
    }

    with pytest.raises(OSError, match="persistence failure"):
        await worker.poll_once()

    await worker.stop()


async def test_start_stop_lifecycle():
    worker, _, _ = make_worker()

    await worker.start()
    with pytest.raises(RuntimeError, match="already started"):
        await worker.start()

    await worker.stop()
    assert worker._consumer.stopped


async def test_failed_processing_stops_future_polls():
    processor = Processor(fail=True)
    worker, _, offsets = make_worker(processor)

    await worker.start()
    await worker._consumer.listener.on_partitions_assigned({TP()})

    worker._consumer.batches = {
        TP(): [Record(10, {"id": "failed"})]
    }

    with pytest.raises(OSError, match="persistence failure"):
        await worker.poll_once()

    assert worker._running is False
    assert await worker.poll_once() == 0
    assert len(processor.calls) == 1

    await worker.stop()


async def test_shutdown_prevents_new_dispatch():
    worker, processor, offsets = make_worker()

    await worker.start()
    await worker._consumer.listener.on_partitions_assigned({TP()})
    await worker.stop()

    worker._consumer.batches = {
        TP(): [Record(10, {"id": "after-stop"})]
    }

    assert await worker.poll_once() == 0
    assert processor.calls == []


async def test_stop_is_idempotent():
    worker, _, _ = make_worker()

    await worker.start()
    await worker.stop()
    await worker.stop()

    assert worker._consumer.stopped is True


async def test_fetch_or_deserialization_error_stops_worker():
    worker, processor, _ = make_worker()
    await worker.start()

    async def broken_fetch(**kwargs):
        raise ValueError("invalid Kafka JSON payload")

    worker._consumer.getmany = broken_fetch
    with pytest.raises(ValueError, match="invalid Kafka JSON"):
        await worker.poll_once()

    assert worker._running is False
    assert await worker.poll_once() == 0
    assert processor.calls == []
    await worker.stop()


async def test_production_rejects_cleartext_kafka_without_override(monkeypatch):
    from app.core.kafka_security import KafkaTransportError

    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("KAFKA_SECURITY_PROTOCOL", "PLAINTEXT")
    monkeypatch.delenv("AISOC_ALLOW_CLEARTEXT_KAFKA", raising=False)
    offsets = OffsetTracker()

    with pytest.raises(KafkaTransportError, match="on the wire in the clear"):
        DurableLakeWorker(
            processor=Processor(),
            offsets=offsets,
            bootstrap_servers="localhost:9092",
            topic="raw-events",
            group_id="aegis-lake-test",
            existing_fusion_group="aegis-fusion",
            consumer_factory=FakeConsumer,
        )


async def test_explicit_tls_transport_is_passed_to_consumer(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("KAFKA_SECURITY_PROTOCOL", "SSL")
    monkeypatch.delenv("AISOC_ALLOW_CLEARTEXT_KAFKA", raising=False)
    worker = DurableLakeWorker(
        processor=Processor(),
        offsets=OffsetTracker(),
        bootstrap_servers="localhost:9093",
        topic="raw-events",
        group_id="aegis-lake-test",
        existing_fusion_group="aegis-fusion",
        consumer_factory=FakeConsumer,
    )
    assert worker._consumer.kwargs["security_protocol"] == "SSL"
    assert worker._consumer.kwargs["ssl_context"].verify_mode != 0
    assert worker._consumer.kwargs["ssl_context"].check_hostname is True


async def test_invalid_kafka_transport_fails_before_consumer_creation(monkeypatch):
    from app.core.kafka_security import KafkaTransportError

    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("KAFKA_SECURITY_PROTOCOL", "INVALID_PROTOCOL")
    monkeypatch.delenv("AISOC_ALLOW_CLEARTEXT_KAFKA", raising=False)
    created = []

    def recording_factory(**kwargs):
        created.append(kwargs)
        return FakeConsumer(**kwargs)

    with pytest.raises(KafkaTransportError, match="not one of"):
        DurableLakeWorker(
            processor=Processor(),
            offsets=OffsetTracker(),
            bootstrap_servers="localhost:9092",
            topic="raw-events",
            group_id="aegis-lake-test",
            existing_fusion_group="aegis-fusion",
            consumer_factory=recording_factory,
        )
    assert created == []


async def test_worker_rejects_missing_kafka_connection_parameters():
    for topic, bootstrap in [("", "localhost:9092"), ("raw-events", "")]:
        with pytest.raises(ValueError, match="required"):
            DurableLakeWorker(
                processor=Processor(),
                offsets=OffsetTracker(),
                bootstrap_servers=bootstrap,
                topic=topic,
                group_id="aegis-lake-test",
                existing_fusion_group="aegis-fusion",
                consumer_factory=FakeConsumer,
                security_kwargs={},
            )


async def test_worker_run_failure_always_closes_consumer():
    processor = Processor(fail=True)
    worker, _, _ = make_worker(processor)
    await worker.start()
    await worker._consumer.listener.on_partitions_assigned({TP()})
    worker._consumer.batches = {TP(): [Record(10, {"id": "failed"})]}

    with pytest.raises(OSError, match="persistence failure"):
        await worker.run()

    assert worker._consumer.stopped is True
    assert worker._started is False
    assert worker._running is False


async def test_worker_run_requires_successful_start():
    worker, _, _ = make_worker()
    with pytest.raises(RuntimeError, match="Start the worker"):
        await worker.run()
