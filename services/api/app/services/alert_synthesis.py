"""Direct-write alert synthesis and normalization.

Extracts normalized alert fields, entity coordinates, bounded timestamps,
and severities from submitted batches or standalone sample scenarios.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from app.models.alert import Alert
from app.services.timestamp_bounds import coerce_with_bounds, now_utc

# Map vendor-native severity strings to the canonical AiSOC severity ladder.
# Keep this in sync with the five-tier ladder documented in AGENTS.md
# (info | low | medium | high | critical).
_SEVERITY_MAP: dict[str, str] = {
    "info": "info",
    "informational": "info",
    "debug": "info",
    "low": "low",
    "minor": "low",
    "warning": "low",
    "medium": "medium",
    "moderate": "medium",
    "warn": "medium",
    "high": "high",
    "error": "high",
    "major": "high",
    "critical": "critical",
    "crit": "critical",
    "severe": "critical",
    "fatal": "critical",
    "emergency": "critical",
}

_SEVERITY_PRIORITY: dict[str, int] = {
    "info": 10,
    "low": 30,
    "medium": 50,
    "high": 75,
    "critical": 95,
}


def _normalize_severity(raw: str | None) -> str:
    if not raw:
        return "medium"
    return _SEVERITY_MAP.get(raw.strip().lower(), "medium")


def _max_severity(values: list[str]) -> str:
    """Pick the highest severity from a list using the canonical ladder."""
    ladder = ["info", "low", "medium", "high", "critical"]
    best = "info"
    for v in values:
        if ladder.index(v) > ladder.index(best):
            best = v
    return best


def _coerce_published(event: dict[str, Any], now: datetime | None = None) -> tuple[datetime | None, bool]:
    """Extract a bounded event timestamp from an OCSF / Okta / generic event dict."""
    return coerce_with_bounds(event, now=now)


def synthesise_alert_from_events(
    *,
    tenant_id: uuid.UUID,
    events: list[dict[str, Any]],
    connector_type: str | None,
    override_title: str | None,
    override_description: str | None,
    override_severity: str | None,
    override_tags: list[str] | None,
    idempotency_key: str | None = None,
) -> Alert:
    """Build a single ``Alert`` row that represents the event batch.

    The shape of incoming events is intentionally loose - raw OCSF, Okta system-log,
    generic events with top-level fields (user_name, src_ip, host), or sample scenarios.
    """
    first = events[0] if events else {}

    # Title
    title = override_title or first.get("displayMessage") or first.get("eventType") or first.get("name") or "AiSOC submitted alert"

    # Severity: pick highest unless overridden
    severities = [_normalize_severity(e.get("severity")) for e in events]
    severity = _normalize_severity(override_severity) if override_severity else (_max_severity(severities) if severities else "medium")
    priority = _SEVERITY_PRIORITY[severity]

    # Description
    description = override_description or (f"Submitted via aisoc submit / API. {len(events)} event(s) in batch. First event: {title}.")

    # Affected entities
    affected_ips: list[str] = []
    affected_hosts: list[str] = []
    affected_users: list[str] = []
    earliest: datetime | None = None
    latest: datetime | None = None
    now = now_utc()
    any_clamped = False

    for event in events:
        actor = event.get("actor") or {}
        client = event.get("client") or {}

        # User: check actor identifiers or top-level user fields
        actor_identifiers = [
            actor[key] for key in ("alternateId", "displayName", "email", "name", "id") if isinstance(actor.get(key), str) and actor[key]
        ]
        if not actor_identifiers:
            user = event.get("user_name") or event.get("user") or event.get("username")
            if isinstance(user, str) and user:
                actor_identifiers = [user]
        if actor_identifiers and not any(ident in affected_users for ident in actor_identifiers):
            affected_users.append(actor_identifiers[0])

        # IP from client or event
        ip = client.get("ipAddress") or client.get("ip") or event.get("src_ip") or event.get("ip")
        if isinstance(ip, str) and ip and ip not in affected_ips:
            affected_ips.append(ip)

        # Host from client geo or device or event
        geo = client.get("geographicalContext") or {}
        host_hint = client.get("device") or client.get("id") or geo.get("city") or event.get("host") or event.get("hostname")
        if isinstance(host_hint, str) and host_hint and host_hint not in affected_hosts:
            affected_hosts.append(host_hint)

        # Timestamps - bounded
        ts, clamped = _coerce_published(event, now=now)
        if clamped:
            any_clamped = True
        if ts is not None:
            if earliest is None or ts < earliest:
                earliest = ts
            if latest is None or ts > latest:
                latest = ts

    event_time = latest or earliest or now
    first_seen = earliest or now
    last_seen = latest or now

    tags = list(override_tags or [])
    if "submitted" not in tags:
        tags.append("submitted")
    if connector_type and connector_type not in tags:
        tags.append(connector_type)
    if any_clamped and "ts-clamped" not in tags:
        tags.append("ts-clamped")

    entities: list[dict[str, str]] = []
    for ip in affected_ips:
        entities.append({"type": "ip", "value": ip})
    for host in affected_hosts:
        entities.append({"type": "host", "value": host})
    for user in affected_users:
        entities.append({"type": "user", "value": user})

    base_raw = dict(first.get("raw_event")) if isinstance(first.get("raw_event"), dict) else {}
    raw_event = {
        **base_raw,
        "events": events,
        "connector_type": connector_type,
        "source": base_raw.get("source") or "aisoc-submit-api",
        "timestamps_clamped": any_clamped,
    }

    return Alert(
        tenant_id=tenant_id,
        title=title,
        description=description,
        severity=severity,
        status="new",
        priority=priority,
        category="identity" if "okta" in (connector_type or "").lower() else None,
        connector_type=connector_type,
        mitre_tactics=[],
        mitre_techniques=[],
        ai_recommendations=[],
        affected_ips=affected_ips,
        affected_hosts=affected_hosts,
        affected_users=affected_users,
        entities=entities,
        tags=tags,
        raw_event=raw_event,
        event_time=event_time,
        first_seen=first_seen,
        last_seen=last_seen,
        created_at=now,
        updated_at=now,
        idempotency_key=idempotency_key,
    )


# Alias for backward compatibility
_synthesise_alert_from_events = synthesise_alert_from_events
