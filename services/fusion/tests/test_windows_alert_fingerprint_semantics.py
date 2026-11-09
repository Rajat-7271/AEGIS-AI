"""Windows pilot: distinguish source-event identity from alert deduplication.

These tests document the current fusion semantics; a single alert is not
proof that only one Windows event reached the pipeline.
"""
from uuid import UUID

from app.models.alert import RawAlert


TENANT = UUID("11111111-1111-4111-8111-111111111111")


def test_distinct_windows_records_can_share_alert_fingerprint() -> None:
    first = RawAlert(
        tenant_id=TENANT,
        source="Windows Security",
        title="Windows authentication failure",
        hostname="workstation-01",
        source_event_ids=["winrec:v1:record-101"],
    )
    second = RawAlert(
        tenant_id=TENANT,
        source="Windows Security",
        title="Windows authentication failure",
        hostname="workstation-01",
        source_event_ids=["winrec:v1:record-102"],
    )
    assert first.source_event_ids != second.source_event_ids
    assert first.fingerprint() == second.fingerprint()
    assert first.deterministic_id() == second.deterministic_id()


def test_windows_alert_fingerprint_is_tenant_scoped() -> None:
    kwargs = dict(source="Windows Security", title="Windows authentication failure", hostname="workstation-01")
    first = RawAlert(tenant_id=TENANT, **kwargs)
    second = RawAlert(tenant_id=UUID("22222222-2222-4222-8222-222222222222"), **kwargs)
    assert first.fingerprint() != second.fingerprint()
    assert first.deterministic_id() != second.deterministic_id()
