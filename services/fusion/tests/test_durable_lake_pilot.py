"""Offline pilot launcher guard tests: never connect to Kafka or ClickHouse."""
import pytest

from app.workers.durable_lake_pilot import build_worker


def test_pilot_disabled_by_default(monkeypatch):
    monkeypatch.delenv("AEGIS_DURABLE_LAKE_PILOT_ENABLED", raising=False)
    with pytest.raises(ValueError, match="disabled by default"):
        build_worker()


def test_pilot_rejects_live_topic_before_connecting(monkeypatch):
    from app.core.config import settings

    monkeypatch.setattr(settings, "environment", "development")
    monkeypatch.setenv("AEGIS_DURABLE_LAKE_PILOT_ENABLED", "true")
    monkeypatch.setenv("AEGIS_DURABLE_LAKE_TOPIC", settings.kafka_topic_raw_events)
    monkeypatch.setenv("AEGIS_DURABLE_LAKE_GROUP", "isolated-test")
    with pytest.raises(ValueError, match="live raw-events topic"):
        build_worker()


def test_pilot_rejects_production_before_connecting(monkeypatch):
    from app.core.config import settings

    monkeypatch.setattr(settings, "environment", "production")
    monkeypatch.setenv("AEGIS_DURABLE_LAKE_PILOT_ENABLED", "true")
    with pytest.raises(ValueError, match="non-production"):
        build_worker()


def test_pilot_rejects_existing_fusion_group(monkeypatch):
    from app.core.config import settings

    monkeypatch.setattr(settings, "environment", "development")
    monkeypatch.setenv("AEGIS_DURABLE_LAKE_PILOT_ENABLED", "true")
    monkeypatch.setenv("AEGIS_DURABLE_LAKE_TOPIC", "aegis.synthetic.pilot")
    monkeypatch.setenv("AEGIS_DURABLE_LAKE_GROUP", settings.kafka_consumer_group)
    with pytest.raises(ValueError, match="separate Kafka consumer group"):
        build_worker()


@pytest.mark.parametrize("protocol", ["PLAINTEXT", "SASL_PLAINTEXT"])
def test_pilot_rejects_unencrypted_kafka_before_connecting(monkeypatch, protocol):
    from app.core.config import settings

    monkeypatch.setattr(settings, "environment", "development")
    monkeypatch.setenv("AEGIS_DURABLE_LAKE_PILOT_ENABLED", "true")
    monkeypatch.setenv("AEGIS_DURABLE_LAKE_TOPIC", "aegis.synthetic.pilot")
    monkeypatch.setenv("AEGIS_DURABLE_LAKE_GROUP", "isolated-test")
    monkeypatch.setenv("KAFKA_SECURITY_PROTOCOL", protocol)
    if protocol == "SASL_PLAINTEXT":
        monkeypatch.setenv("KAFKA_SASL_MECHANISM", "PLAIN")
    with pytest.raises(ValueError, match="TLS-encrypted Kafka transport"):
        build_worker()


def test_pilot_passes_verified_tls_transport_to_worker(monkeypatch):
    """Exercise construction with fakes; no sockets or credentials leave the test."""
    import sys
    import types
    from app.core.config import settings
    from app.workers import durable_lake_pilot as pilot

    monkeypatch.setattr(settings, "environment", "development")
    monkeypatch.setenv("AEGIS_DURABLE_LAKE_PILOT_ENABLED", "true")
    monkeypatch.setenv("AEGIS_DURABLE_LAKE_TOPIC", "aegis.synthetic.pilot")
    monkeypatch.setenv("AEGIS_DURABLE_LAKE_GROUP", "isolated-test")
    monkeypatch.setenv("AEGIS_DURABLE_LAKE_CLICKHOUSE_HOST", "synthetic.invalid")
    monkeypatch.setenv("AEGIS_DURABLE_LAKE_CLICKHOUSE_PORT", "9440")
    monkeypatch.setenv("AEGIS_DURABLE_LAKE_CLICKHOUSE_USER", "synthetic")
    monkeypatch.setenv("AEGIS_DURABLE_LAKE_CLICKHOUSE_PASSWORD", "synthetic-only")
    monkeypatch.setenv("AEGIS_DURABLE_LAKE_KAFKA_BOOTSTRAP", "synthetic.invalid:9093")
    transport = {"security_protocol": "SSL", "ssl_context": object()}
    monkeypatch.setattr(pilot, "kafka_client_kwargs", lambda: transport)
    captured = {}

    def fake_clickhouse_client(**kwargs):
        captured["clickhouse"] = kwargs
        return object()

    def fake_worker(**kwargs):
        captured["worker"] = kwargs
        return "synthetic-worker"

    monkeypatch.setitem(sys.modules, "clickhouse_driver", types.SimpleNamespace(Client=fake_clickhouse_client))
    monkeypatch.setattr(pilot, "DurableLakeWorker", fake_worker)
    assert pilot.build_worker() == "synthetic-worker"
    assert captured["worker"]["security_kwargs"] is transport
    assert captured["worker"]["topic"] == "aegis.synthetic.pilot"
    assert captured["worker"]["group_id"] == "isolated-test"
    assert captured["clickhouse"]["secure"] is True
    assert captured["clickhouse"]["verify"] is True


@pytest.mark.asyncio
async def test_pilot_main_stops_worker_after_run_failure(monkeypatch):
    from app.workers import durable_lake_pilot as pilot

    calls = []

    class FakeWorker:
        async def start(self):
            calls.append("start")

        async def run(self):
            calls.append("run")
            raise OSError("synthetic persistence outage")

        async def stop(self):
            calls.append("stop")

    monkeypatch.setattr(pilot, "build_worker", FakeWorker)
    with pytest.raises(OSError, match="synthetic persistence outage"):
        await pilot.main()
    assert calls == ["start", "run", "stop"]


@pytest.mark.asyncio
async def test_pilot_main_stops_worker_after_cancellation(monkeypatch):
    import asyncio
    from app.workers import durable_lake_pilot as pilot

    calls = []

    class FakeWorker:
        async def start(self):
            calls.append("start")

        async def run(self):
            calls.append("run")
            raise asyncio.CancelledError()

        async def stop(self):
            calls.append("stop")

    monkeypatch.setattr(pilot, "build_worker", FakeWorker)
    with pytest.raises(asyncio.CancelledError):
        await pilot.main()
    assert calls == ["start", "run", "stop"]


@pytest.mark.asyncio
async def test_pilot_main_normal_exit_stops_worker_once(monkeypatch):
    from app.workers import durable_lake_pilot as pilot

    calls = []

    class FakeWorker:
        async def start(self):
            calls.append("start")

        async def run(self):
            calls.append("run")

        async def stop(self):
            calls.append("stop")

    monkeypatch.setattr(pilot, "build_worker", FakeWorker)
    await pilot.main()
    assert calls == ["start", "run", "stop"]
