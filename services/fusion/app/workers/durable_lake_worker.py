"""Opt-in, dedicated Kafka consumer for durable event-lake processing.

No consumer is started on import. The deployment must explicitly construct
and run this worker with a separate Kafka consumer group.
"""
from __future__ import annotations

import asyncio
import json
import time
from typing import Any

from aiokafka import AIOKafkaConsumer

from app.core.kafka_security import kafka_client_kwargs
from app.services.lake_rebalance import LakeRebalanceListener


class DurableLakeWorker:
    def __init__(
        self,
        *,
        processor: Any,
        offsets: Any,
        bootstrap_servers: str,
        topic: str,
        group_id: str,
        existing_fusion_group: str,
        consumer_factory: Any = AIOKafkaConsumer,
        security_kwargs: dict | None = None,
    ) -> None:
        if not group_id or group_id == existing_fusion_group:
            raise ValueError("Lake consumer requires a separate Kafka group")
        if not topic or not bootstrap_servers:
            raise ValueError("Kafka topic and bootstrap servers are required")

        self._processor = processor
        self._offsets = offsets
        self._running = False
        self._started = False
        self._poll_lock = asyncio.Lock()
        self._stop_lock = asyncio.Lock()
        self._processed_total = 0
        self._failures_total = 0
        self._last_success_monotonic = None

        # Resolve security through the existing centralized policy.
        # An injected dictionary is only intended for isolated tests.
        transport = (
            kafka_client_kwargs()
            if security_kwargs is None
            else security_kwargs
        )

        self._consumer = consumer_factory(
            bootstrap_servers=bootstrap_servers,
            group_id=group_id,
            enable_auto_commit=False,
            auto_offset_reset="earliest",
            value_deserializer=lambda raw: json.loads(
                raw.decode("utf-8")
            ),
            **transport,
        )

        self._listener = LakeRebalanceListener(
            processor=processor,
            offsets=offsets,
            consumer=self._consumer,
        )
        self._consumer.subscribe(
            topics=[topic],
            listener=self._listener,
        )

    async def start(self) -> None:
        if self._started:
            raise RuntimeError("Lake worker already started")
        try:
            await self._consumer.start()
        except BaseException:
            # Kafka startup can partially allocate sockets/tasks before failing.
            # Best-effort cleanup must not replace the original startup error.
            try:
                await self._consumer.stop()
            except Exception:
                pass
            raise
        self._started = True
        self._running = True

    async def poll_once(self) -> int:
        """Process one fetched record at a time without skipping failures."""
        async with self._poll_lock:
            if not self._running:
                return 0

            try:
                batches = await self._consumer.getmany(
                    timeout_ms=500,
                    max_records=1,
                )
            except Exception:
                self._failures_total += 1
                # Deserialization, transport, or broker failures must also
                # fail-stop: never continue after an uncertain fetch state.
                self._running = False
                raise
            count = 0

            for tp, records in batches.items():
                for record in records:
                    if not self._running:
                        return count

                    key = (tp.topic, tp.partition)
                    if key not in self._offsets._partitions:
                        continue

                    try:
                        await self._processor.process(
                            consumer=self._consumer,
                            topic_partition=tp,
                            offset=record.offset,
                            message=record.value,
                        )
                    except Exception:
                        self._failures_total += 1
                        # Do not continue polling after a failed record.
                        # A restart/reassignment must replay from the last
                        # successfully committed Kafka offset.
                        self._running = False
                        raise

                    count += 1
                    self._processed_total += 1
                    self._last_success_monotonic = time.monotonic()

            return count

    def health_snapshot(self) -> dict[str, Any]:
        """Non-sensitive worker counters for an external health reporter.

        last_success_age_seconds is null until the first successful record.
        These counters are process-local and reset on restart; consumer lag
        must be monitored independently from Kafka committed offsets.
        """
        return {
            "started": self._started,
            "running": self._running,
            "processed_total": self._processed_total,
            "failures_total": self._failures_total,
            "last_success_age_seconds": (
                None if self._last_success_monotonic is None
                else max(0.0, time.monotonic() - self._last_success_monotonic)
            ),
        }

    async def run(self) -> None:
        if not self._started:
            raise RuntimeError("Start the worker before running")
        try:
            while self._running:
                await self.poll_once()
        finally:
            await self.stop()

    async def stop(self) -> None:
        self._running = False
        async with self._stop_lock:
            if not self._started:
                return

            # Allow an active poll and its processing/commit to complete.
            async with self._poll_lock:
                await self._consumer.stop()
                self._started = False
