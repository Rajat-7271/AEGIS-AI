"""Offline replay experiment: partial acknowledgements and at-least-once delivery.

This is a model of the retry decision, NOT a test of the Go ingestion
service or its storage deduplication. It uses the scheduler's actual
acknowledgement predicate and deterministic synthetic event identities.
"""
from __future__ import annotations

import ast
import json
from pathlib import Path
from typing import Any

root = Path(__file__).resolve().parents[2]
scheduler = root / "services/connectors/app/scheduler.py"
tree = ast.parse(scheduler.read_text(encoding="utf-8"))
functions = [n for n in tree.body if isinstance(n, ast.FunctionDef)
             and n.name == "_acknowledgement_complete"]
if len(functions) != 1:
    raise RuntimeError("Scheduler acknowledgement predicate missing")
namespace = {"Any": Any}
exec(compile(ast.fix_missing_locations(ast.Module(body=functions, type_ignores=[])),
             str(scheduler), "exec"), namespace)
complete = namespace["_acknowledgement_complete"]


def event_key(event: dict) -> tuple[str, str, int]:
    """A synthetic source identity, not a claim about backend dedup keys."""
    system = event["System"]
    return system["Computer"], system["Channel"], system["EventRecordID"]


events = [
    {"System": {"Computer": "host-a", "Channel": "Security", "EventRecordID": n}}
    for n in (100, 101, 102)
]
# First attempt: receiver accepts 100 and 101, rejects 102.
first_ack = {"accepted": 2, "rejected": 1}
assert not complete(first_ack, len(events))
checkpoint_advanced = False
# On retry, the same three records must be available for replay.
replay = list(events)
assert [event_key(e) for e in replay] == [event_key(e) for e in events]
second_ack = {"accepted": 3, "rejected": 0}
assert complete(second_ack, len(replay))
checkpoint_advanced = True
# The first two were delivered twice across attempts. A real receiver must
# deduplicate these; acknowledgement gating alone does not provide that.
delivered = events[:2] + replay
unique = {event_key(e) for e in delivered}
assert len(delivered) == 5 and len(unique) == 3 and checkpoint_advanced
print(json.dumps({
    "status": "passed",
    "synthetic_events": 3,
    "delivery_attempts": 2,
    "deliveries_including_replays": 5,
    "unique_source_records": 3,
    "duplicate_deliveries_requiring_backend_idempotency": 2,
    "checkpoint_advanced_only_after_complete_ack": True,
    "backend_dedup_verified": False,
    "network_requests": 0,
    "real_events_sent": 0,
}, indent=2))
