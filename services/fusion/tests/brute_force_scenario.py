"""Small, deterministic, labelled authentication scenarios for Fusion replay.

Each label belongs to one login sequence (the scoring unit), not an individual
event: the windowed rule is expected to alert once after observing a sequence
of failures. Events use the same normalized Kafka envelope published by
services/ingest, and carry no ground-truth fields in the detector-visible data.

The paired evaluation contains two malicious sequences (five or six failures
followed by success) and three benign retry sequences (two to four failures).
Its expected result is two detected malicious scenarios and no benign alerts.
This is a deterministic smoke/evaluation fixture, not a statistically
meaningful estimate of production detection quality.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Literal

GROUND_TRUTH = Literal["malicious", "benign"]
BASE_TIME = datetime(2026, 1, 15, 12, 0, tzinfo=UTC)
TENANT_ID = "8ac9f3f8-6ee3-4f77-ae17-c725e1d72a10"


@dataclass(frozen=True)
class ScenarioEvent:
    scenario_id: str
    ground_truth: GROUND_TRUTH
    event: dict


def build_events() -> tuple[ScenarioEvent, ...]:
    """Return the same ordered attack and benign control events every time."""
    scenarios = (
        # Two independent positive cases prevent one fixed account or source
        # from being the only condition exercised by the rule.
        ("bruteforce-alice", "malicious", "alice@example.test", "203.0.113.41", "vpn-gw-01", 5, True),
        ("bruteforce-bob", "malicious", "bob@example.test", "198.51.100.42", "vpn-gw-02", 6, True),
        # Normal retries stay below the production threshold of five per user.
        ("benign-carol", "benign", "carol@example.test", "192.0.2.11", "vpn-gw-01", 3, False),
        ("benign-dave", "benign", "dave@example.test", "192.0.2.12", "vpn-gw-02", 4, False),
        ("benign-erin", "benign", "erin@example.test", "192.0.2.13", "vpn-gw-03", 2, False),
    )
    rows: list[ScenarioEvent] = []
    event_index = 0
    for scenario_id, label, user, source_ip, host, failures, succeeds in scenarios:
        for attempt in range(failures + int(succeeds)):
            outcome = "failure" if attempt < failures else "success"
            event_id = f"sentinel-mvp:{scenario_id}:{attempt + 1:02d}"
            occurred = BASE_TIME + timedelta(seconds=event_index * 20)
            raw_event = {
                "event_type": "authentication",
                "outcome": outcome,
                "user": user,
                "src_ip": source_ip,
                "host": host,
                "event_time": occurred.isoformat().replace("+00:00", "Z"),
            }
            event = {
                "schema_version": "v1",
                "event_id": event_id,
                "tenant_id": TENANT_ID,
                "connector_id": "sentinel-mvp-synthetic",
                "ocsf_event": {
                    "class_uid": 3002,
                    "class_name": "Authentication",
                    "category_uid": 3,
                    "severity_id": 1,
                    "time": raw_event["event_time"],
                    "tenant_uid": TENANT_ID,
                    "metadata": {"uid": event_id, "product": {"name": "Sentinel AI evaluation"}},
                    "raw_data": json.dumps(raw_event, sort_keys=True),
                },
            }
            rows.append(ScenarioEvent(scenario_id, label, event))
            event_index += 1
    return tuple(rows)
