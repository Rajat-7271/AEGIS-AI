"""Direct sample data loader for standalone mode.

When AISOC_DISABLE_KAFKA=true (or standalone mode is enabled), this module
synthesises the five sample scenarios and persists them directly using the
exact same alert synthesis and idempotency semantics as the submit endpoint,
without requiring Kafka, the Go ingest worker, or ClickHouse.
"""

from __future__ import annotations

import logging
import os
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import and_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.alert import Alert
from app.services.alert_synthesis import synthesise_alert_from_events

logger = logging.getLogger(__name__)


def is_standalone_mode() -> bool:
    """Whether the system is running in standalone / free-tier mode without Kafka."""
    if getattr(settings, "AISOC_DISABLE_KAFKA", False):
        return True
    env_kafka = os.getenv("AISOC_DISABLE_KAFKA", "").strip().lower()
    if env_kafka in ("1", "true", "yes"):
        return True
    env_standalone = os.getenv("AISOC_STANDALONE", "").strip().lower()
    return env_standalone in ("1", "true", "yes")


async def load_standalone_sample_data(
    *,
    db: AsyncSession,
    tenant_id: str | uuid.UUID,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Persist the 5 sample scenarios directly for the given tenant.

    Idempotent: uses deterministic idempotency keys (`sample-{scenario.key}`)
    to ensure repeated clicks return the existing sample alerts without
    creating duplicate rows.
    """
    from app.services.sample_data import SAMPLE_CONNECTOR, SCENARIOS

    tenant_uuid = uuid.UUID(str(tenant_id)) if not isinstance(tenant_id, uuid.UUID) else tenant_id
    base = now or datetime.now(UTC)

    accepted = 0
    scenarios_meta: list[dict[str, Any]] = []

    for index, scenario in enumerate(SCENARIOS):
        scenarios_meta.append(
            {
                "key": scenario.key,
                "title": scenario.title,
                "severity": scenario.severity,
                "why": scenario.rationale,
            }
        )

        idempotency_key = f"sample-{scenario.key}"

        # Check for existing alert under this tenant and idempotency key
        stmt = select(Alert).where(
            and_(
                Alert.tenant_id == tenant_uuid,
                Alert.idempotency_key == idempotency_key,
            )
        )
        res = await db.execute(stmt)
        cached = res.scalar_one_or_none()
        if cached is not None:
            accepted += 1
            continue

        when = base - timedelta(minutes=(len(SCENARIOS) - index) * 11)
        event = {
            "source": SAMPLE_CONNECTOR,
            "external_id": f"sample-{scenario.key}-{int(when.timestamp())}",
            "title": scenario.title,
            "description": scenario.description,
            "severity": scenario.severity,
            "created_at": when.isoformat(),
            "timestamp": when.isoformat(),
            "time": when.isoformat(),
            "published": when.isoformat(),
            "user_name": scenario.fields.get("user_name"),
            "src_ip": scenario.fields.get("src_ip"),
            "host": scenario.fields.get("host"),
            "actor": {
                "displayName": scenario.fields.get("user_name"),
                "email": scenario.fields.get("user_name"),
                "alternateId": scenario.fields.get("user_name"),
            }
            if scenario.fields.get("user_name")
            else {},
            "client": {
                "ipAddress": scenario.fields.get("src_ip"),
                "device": scenario.fields.get("host"),
            },
            "raw_event": {
                **scenario.fields,
                "aisoc_sample_data": True,
                "aisoc_sample_scenario": scenario.key,
                "source": "aisoc-sample-standalone",
            },
            **scenario.fields,
        }

        alert = synthesise_alert_from_events(
            tenant_id=tenant_uuid,
            events=[event],
            connector_type=SAMPLE_CONNECTOR,
            override_title=scenario.title,
            override_description=scenario.description,
            override_severity=scenario.severity,
            override_tags=["submitted", SAMPLE_CONNECTOR, scenario.key],
            idempotency_key=idempotency_key,
        )

        db.add(alert)
        try:
            await db.flush()
            accepted += 1
        except IntegrityError:
            # Concurrent race inserting the same idempotency_key
            await db.rollback()
            retry_res = await db.execute(stmt)
            if retry_res.scalar_one_or_none() is not None:
                accepted += 1
            else:
                logger.exception("Failed to insert sample alert for scenario %s", scenario.key)
                raise

    await db.commit()

    logger.info(
        "sample_data.loaded_standalone",
        extra={
            "tenant_id": str(tenant_uuid),
            "accepted": accepted,
        },
    )

    return {
        "accepted": accepted,
        "rejected": 0,
        "scenarios": scenarios_meta,
        "note": ("Sample data loaded directly into the estate. Five scenarios are now available in your alert queue."),
    }
