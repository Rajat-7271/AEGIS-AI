"""Small labelled replay through the production UEBA extractor and scorer.

The replay uses the normalized OCSF event shape consumed from
``aisoc.raw_events``. Its labels live on the test cases and never enter the
event sent to ``feature_extraction.extract`` or ``ScoringService``. A fake
async session provides tenant-keyed in-memory persistence; the production
feature extraction, Welford baseline, z-score, threshold, and anomaly model
remain under test.

Run from ``services/ueba`` with ``pytest -s tests/test_labeled_scoring_replay.py``.
The four evaluation observations are intentionally a smoke set, not a
statistically meaningful performance estimate.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from app.core.config import settings
from app.models.ueba import EntityBaseline, UEBAAnomaly
from app.services.feature_extraction import extract
from app.services.scoring import ScoringService


@dataclass(frozen=True)
class _LabelledObservation:
    case_id: str
    tenant_id: uuid.UUID
    entity_id: str
    ground_truth_anomaly: bool
    event: dict[str, Any]


class _ScalarResult:
    def __init__(self, row: EntityBaseline | None) -> None:
        self._row = row

    def scalar_one_or_none(self) -> EntityBaseline | None:
        return self._row


class _MemorySession:
    """Only persistence is faked; scorer and baseline services are real."""

    def __init__(self) -> None:
        self.baselines: dict[tuple[uuid.UUID, str, str], EntityBaseline] = {}
        self.anomalies: list[UEBAAnomaly] = []

    async def execute(self, statement: Any) -> _ScalarResult:
        model = statement.column_descriptions[0]["entity"]
        if model is not EntityBaseline:
            raise AssertionError(f"unexpected model query in replay: {model}")
        where = statement.whereclause
        clauses = getattr(where, "clauses", (where,))
        values = {clause.left.key: clause.right.value for clause in clauses}
        key = (values["tenant_id"], values["entity_type"], values["entity_id"])
        return _ScalarResult(self.baselines.get(key))

    def add(self, row: EntityBaseline | UEBAAnomaly) -> None:
        if isinstance(row, EntityBaseline):
            key = (row.tenant_id, row.entity_type, row.entity_id)
            self.baselines[key] = row
        else:
            self.anomalies.append(row)

    async def flush(self) -> None:
        return None


def _event(tenant_id: uuid.UUID, entity_id: str, event_id: str, bytes_out: float, index: int) -> dict[str, Any]:
    occurred = datetime(2026, 2, 2, 12, tzinfo=UTC) + timedelta(minutes=index)
    raw = {
        "event_type": "authentication",
        "outcome": "success",
        "user": entity_id,
        "bytes_out": bytes_out,
        "event_time": occurred.isoformat().replace("+00:00", "Z"),
    }
    return {
        "schema_version": "v1",
        "event_id": event_id,
        "tenant_id": str(tenant_id),
        "ocsf_event": {
            "tenant_uid": str(tenant_id),
            "class_uid": 3002,
            "class_name": "Authentication",
            "time": raw["event_time"],
            "metadata": {"uid": event_id},
            "raw_data": json.dumps(raw, sort_keys=True),
        },
    }


async def _score_event(scorer: ScoringService, event: dict[str, Any]) -> UEBAAnomaly | None:
    extracted = extract(event)
    assert extracted is not None, f"production extractor rejected event {event['event_id']}"
    assert "ground_truth_anomaly" not in extracted.features
    assert "bytes_out" in extracted.features
    return await scorer.score_event(
        tenant_id=uuid.UUID(extracted.tenant_id),
        entity_type=extracted.entity_type,
        entity_id=extracted.entity_id,
        event_type=extracted.event_type,
        features=extracted.features,
        source_event_id=extracted.source_event_id,
    )


@pytest.mark.asyncio
async def test_labeled_replay_measures_production_ueba_scoring() -> None:
    tenant_a = uuid.UUID("b7634568-360f-4f65-a531-8a55d8ee2170")
    tenant_b = uuid.UUID("79d4897a-61fb-4095-9029-8e997d453dd5")
    samples = max(30, settings.min_baseline_samples)
    session = _MemorySession()
    scorer = ScoringService(session)

    # The same principal exists in both tenants. Tenant A has a small-volume
    # baseline; tenant B has a larger-volume baseline. They must not share it.
    entities = (
        (tenant_a, "alice@example.test", 100.0, 10.0),
        (tenant_b, "alice@example.test", 10_000.0, 1_000.0),
        (tenant_a, "bob@example.test", 1_000.0, 100.0),
        (tenant_b, "bob@example.test", 20_000.0, 2_000.0),
    )
    offsets = (-2, -1, 0, 1, 2)
    for tenant_id, entity_id, center, spread in entities:
        for index in range(samples):
            value = center + offsets[index % len(offsets)] * spread
            baseline_result = await _score_event(
                scorer,
                _event(tenant_id, entity_id, f"warm:{tenant_id}:{entity_id}:{index}", value, index),
            )
            assert baseline_result is None, "normal baseline observations unexpectedly emitted an anomaly"

    cases = (
        _LabelledObservation(
            "tenant-a-alice-egress-spike",
            tenant_a,
            "alice@example.test",
            True,
            _event(tenant_a, "alice@example.test", "eval:tenant-a-alice", 2_000.0, samples + 1),
        ),
        _LabelledObservation(
            "tenant-b-alice-routine-egress",
            tenant_b,
            "alice@example.test",
            False,
            _event(tenant_b, "alice@example.test", "eval:tenant-b-alice", 10_000.0, samples + 1),
        ),
        _LabelledObservation(
            "tenant-a-bob-egress-spike",
            tenant_a,
            "bob@example.test",
            True,
            _event(tenant_a, "bob@example.test", "eval:tenant-a-bob", 8_000.0, samples + 1),
        ),
        _LabelledObservation(
            "tenant-b-bob-routine-egress",
            tenant_b,
            "bob@example.test",
            False,
            _event(tenant_b, "bob@example.test", "eval:tenant-b-bob", 20_000.0, samples + 1),
        ),
    )

    observed: dict[str, bool] = {}
    for case in cases:
        assert "ground_truth_anomaly" not in case.event
        result = await _score_event(scorer, case.event)
        observed[case.case_id] = result is not None

    counts = {"TP": 0, "FP": 0, "FN": 0, "TN": 0}
    labels_to_outcome = {
        (True, True): "TP",
        (False, True): "FP",
        (True, False): "FN",
        (False, False): "TN",
    }
    for case in cases:
        predicted = observed[case.case_id]
        outcome = (case.ground_truth_anomaly, predicted)
        counts[labels_to_outcome[outcome]] += 1

    positives = sum(case.ground_truth_anomaly for case in cases)
    negatives = len(cases) - positives
    report = {
        **counts,
        "detection_rate": counts["TP"] / positives if positives else None,
        "false_positive_rate": counts["FP"] / negatives if negatives else None,
    }
    print(f"UEBA labeled replay (n={len(cases)}): {json.dumps(report, sort_keys=True)}")

    assert report == {
        "TP": 2,
        "FP": 0,
        "FN": 0,
        "TN": 2,
        "detection_rate": 1.0,
        "false_positive_rate": 0.0,
    }, f"observed production-scorer replay results: {report}; predictions={observed}"

    alice_a = session.baselines[(tenant_a, "user", "alice@example.test")]
    alice_b = session.baselines[(tenant_b, "user", "alice@example.test")]
    assert alice_a.feature_stats["bytes_out"]["mean"] != alice_b.feature_stats["bytes_out"]["mean"]
