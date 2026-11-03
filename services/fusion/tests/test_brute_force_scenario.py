"""Evaluate deterministic brute-force controls through Fusion's real consumer."""

from __future__ import annotations

import json
from collections import Counter
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from app.core.config import settings
from app.services.windowed_detection import WindowedDetectionEngine, load_window_rules
from app.workers.consumer import FusionWorker

from .brute_force_scenario import build_events


class _MemoryRedis:
    """In-memory subset of Redis sorted-set operations used by the rule."""

    def __init__(self) -> None:
        self.zsets: dict[str, dict[str, float]] = {}
        self.strings: dict[str, str] = {}

    async def zadd(self, key: str, mapping: dict[str, float]) -> None:
        self.zsets.setdefault(key, {}).update(mapping)

    async def zremrangebyscore(self, key: str, minimum: float, maximum: float) -> None:
        values = self.zsets.get(key, {})
        for member in [member for member, score in values.items() if minimum <= score <= maximum]:
            del values[member]

    async def expire(self, _key: str, _seconds: int) -> None:
        return None

    async def zcard(self, key: str) -> int:
        return len(self.zsets.get(key, {}))

    async def set(self, key: str, value: str, *, nx: bool = False, ex: int | None = None):
        if nx and key in self.strings:
            return None
        self.strings[key] = value
        return True


def _metrics(events, detected_scenarios: set[str]) -> dict[str, int | float]:
    truth_by_scenario = {row.scenario_id: row.ground_truth for row in events}
    confusion: Counter[str] = Counter(
        {"true_positive": 0, "false_positive": 0, "false_negative": 0, "true_negative": 0}
    )
    outcome_by_label = {
        ("malicious", True): "true_positive",
        ("malicious", False): "false_negative",
        ("benign", True): "false_positive",
        ("benign", False): "true_negative",
    }
    for scenario_id, truth in truth_by_scenario.items():
        detected = scenario_id in detected_scenarios
        confusion[outcome_by_label[(truth, detected)]] += 1
    positives = confusion["true_positive"] + confusion["false_negative"]
    negatives = confusion["false_positive"] + confusion["true_negative"]
    return {
        **confusion,
        "malicious_scenarios": positives,
        "benign_scenarios": negatives,
        "detection_rate": confusion["true_positive"] / positives if positives else 0.0,
        "false_positive_rate": confusion["false_positive"] / negatives if negatives else 0.0,
    }


def test_scenario_is_repeatable_and_has_ordered_labelled_events() -> None:
    first = build_events()
    second = build_events()
    assert first == second
    assert len({row.event["event_id"] for row in first}) == len(first)
    assert [row.event["ocsf_event"]["time"] for row in first] == sorted(row.event["ocsf_event"]["time"] for row in first)
    assert {row.ground_truth for row in first} == {"malicious", "benign"}
    assert all("ground_truth" not in row.event["ocsf_event"]["raw_data"] for row in first)
    assert all(
        {"user", "src_ip", "host", "outcome"} <= set(json.loads(row.event["ocsf_event"]["raw_data"]))
        for row in first
    )


@pytest.mark.asyncio
async def test_labelled_scenarios_measure_observed_fusion_detection_and_false_alerts() -> None:
    events = build_events()
    brute_force_rule = tuple(rule for rule in load_window_rules() if rule.id == "wd-bruteforce-auth")
    assert len(brute_force_rule) == 1, "the production brute-force rule is missing"

    worker = FusionWorker(
        engine=SimpleNamespace(process=AsyncMock()),
        windowed_detector=WindowedDetectionEngine(_MemoryRedis(), rules=brute_force_rule, sequences=()),
    )
    detected_scenarios: set[str] = set()
    scenario_by_event_id = {row.event["event_id"]: row.scenario_id for row in events}

    async def capture_detection(alert, *, source_event_id=None, session=None):
        assert source_event_id
        assert session is None
        if alert.rule_id == "wd-bruteforce-auth":
            detected_scenarios.add(scenario_by_event_id[source_event_id])

    worker._fuse_and_persist = capture_detection
    for row in events:
        await worker._process_message(row.event, topic=settings.kafka_topic_raw_events)

    scores = _metrics(events, detected_scenarios)
    assert scores == {
        "true_positive": 2,
        "false_positive": 0,
        "false_negative": 0,
        "true_negative": 3,
        "malicious_scenarios": 2,
        "benign_scenarios": 3,
        "detection_rate": 1.0,
        "false_positive_rate": 0.0,
    }, f"observed Fusion scenario metrics: {scores}; detections: {sorted(detected_scenarios)}"
