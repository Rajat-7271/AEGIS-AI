"""Real ClickHouse contract tests for the durable lake sink (isolated CI only)."""
import uuid

import pytest
from clickhouse_driver import Client
from app.services.durable_lake_sink import DurableLakeSink, LakePersistenceError

pytestmark = pytest.mark.asyncio


def message(tenant, event_id):
    return {
        "id": str(event_id),
        "tenant_id": str(tenant),
        "connector_type": "windows-security",
        "ocsf_event": {
            "class_uid": 3002,
            "category_uid": 3,
            "severity_id": 2,
            "severity": "Informational",
            "activity_id": 1,
            "time": "2026-11-09T00:00:00Z",
            "metadata": {"product": {"name": "windows-security"}},
        },
    }


async def test_real_clickhouse_write_and_replay_dedup():
    db = Client(host="127.0.0.1", port=19000, database="aisoc")
    tenant, event_id = uuid.uuid4(), uuid.uuid4()
    item = message(tenant, event_id)
    try:
        sink = DurableLakeSink(db)
        await sink.persist(item)
        await sink.persist(item)
        rows = db.execute(
            "SELECT event_id, tenant_id, connector_type FROM aisoc.raw_events FINAL "
            "WHERE event_id = %(event)s AND tenant_id = %(tenant)s",
            {"event": str(event_id), "tenant": str(tenant)},
        )
        assert len(rows) == 1
        assert str(rows[0][0]) == str(event_id)
        assert str(rows[0][1]) == str(tenant)
        assert rows[0][2] == "windows-security"
    finally:
        db.disconnect()


async def test_failed_insert_does_not_acknowledge():
    # ClickHouse client uses a deliberately unreachable local port.
    db = Client(host="127.0.0.1", port=19999, database="aisoc", connect_timeout=1)
    try:
        with pytest.raises(LakePersistenceError, match="not acknowledged"):
            await DurableLakeSink(db).persist(message(uuid.uuid4(), uuid.uuid4()))
    finally:
        db.disconnect()


async def test_tenant_isolation_for_shared_event_id():
    db = Client(host="127.0.0.1", port=19000, database="aisoc")
    tenant_a, tenant_b, event_id = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    try:
        sink = DurableLakeSink(db)
        await sink.persist(message(tenant_a, event_id))
        await sink.persist(message(tenant_b, event_id))
        for tenant in (tenant_a, tenant_b):
            rows = db.execute(
                "SELECT tenant_id FROM aisoc.raw_events FINAL "
                "WHERE event_id = %(event)s AND tenant_id = %(tenant)s",
                {"event": str(event_id), "tenant": str(tenant)},
            )
            assert len(rows) == 1
            assert str(rows[0][0]) == str(tenant)
    finally:
        db.disconnect()
