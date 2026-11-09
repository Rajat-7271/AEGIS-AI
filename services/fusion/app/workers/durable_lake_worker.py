"""Opt-in, dedicated Kafka consumer for durable event-lake processing.

No consumer is started on import. The deployment must explicitly construct
and run this worker with a separate Kafka consumer group.
"""
from __future__ import annotations

import asyncio
import json
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
        await self._consumer.start()
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
                        # Do not continue polling after a failed record.
                        # A restart/reassignment must replay from the last
                        # successfully committed Kafka offset.
                        self._running = False
                        raise

                    count += 1

            return count

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
