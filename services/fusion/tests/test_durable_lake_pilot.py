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
