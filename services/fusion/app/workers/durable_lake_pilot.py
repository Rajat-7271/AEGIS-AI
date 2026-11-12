"""Explicit, isolated synthetic-pilot entrypoint for the durable lake worker.

Not imported by the normal fusion application or any deployment manifest.
Invoke manually only after configuring a dedicated non-production Kafka topic,
consumer group, and verified-TLS ClickHouse endpoint.
"""
from __future__ import annotations

import asyncio
import os

from app.core.config import settings
from app.core.kafka_security import kafka_client_kwargs
from app.services.durable_lake_processor import DurableLakeProcessor
from app.services.durable_lake_sink import DurableLakeSink
from app.services.lake_offsets import OffsetTracker
from app.workers.durable_lake_worker import DurableLakeWorker


def _required(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise ValueError(f"{name} must be explicitly configured")
    return value


def build_worker() -> DurableLakeWorker:
    """Validate opt-in configuration before constructing network clients."""
    if os.getenv("AEGIS_DURABLE_LAKE_PILOT_ENABLED") != "true":
        raise ValueError("Durable lake pilot is disabled by default")
    if settings.environment.lower() not in {"development", "test", "testing"}:
        raise ValueError("Durable lake pilot launcher is limited to non-production test environments")

    topic = _required("AEGIS_DURABLE_LAKE_TOPIC")
    group = _required("AEGIS_DURABLE_LAKE_GROUP")
    if group == settings.kafka_consumer_group:
        raise ValueError("Durable lake must use a separate Kafka consumer group")
    if topic == settings.kafka_topic_raw_events:
        raise ValueError("Pilot must not subscribe to the live raw-events topic")

    transport = kafka_client_kwargs()
    if transport.get("security_protocol") not in {"SSL", "SASL_SSL"}:
        raise ValueError("Durable lake pilot requires TLS-encrypted Kafka transport")

    host = _required("AEGIS_DURABLE_LAKE_CLICKHOUSE_HOST")
    port = int(_required("AEGIS_DURABLE_LAKE_CLICKHOUSE_PORT"))
    user = _required("AEGIS_DURABLE_LAKE_CLICKHOUSE_USER")
    password = _required("AEGIS_DURABLE_LAKE_CLICKHOUSE_PASSWORD")
    bootstrap = _required("AEGIS_DURABLE_LAKE_KAFKA_BOOTSTRAP")
    if not (1 <= port <= 65535):
        raise ValueError("ClickHouse port is invalid")

    from clickhouse_driver import Client

    client = Client(
        host=host, port=port, user=user, password=password,
        database="aisoc", secure=True, verify=True,
        connect_timeout=5, send_receive_timeout=15,
    )
    offsets = OffsetTracker()
    processor = DurableLakeProcessor(DurableLakeSink(client), offsets)
    return DurableLakeWorker(
        processor=processor,
        offsets=offsets,
        bootstrap_servers=bootstrap,
        topic=topic,
        group_id=group,
        existing_fusion_group=settings.kafka_consumer_group,
        security_kwargs=transport,
    )


async def main() -> None:
    worker = build_worker()
    await worker.start()
    try:
        await worker.run()
    finally:
        await worker.stop()


if __name__ == "__main__":
    asyncio.run(main())
