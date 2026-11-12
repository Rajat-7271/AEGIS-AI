"""Offline validator tests: no Windows host, services, or secrets required."""
import importlib.util
import json
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[3] / "tools" / "windows" / "validate_export.py"
spec = importlib.util.spec_from_file_location("windows_validate_export", SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def event(record_id=1, event_id=4624):
    return {"System": {"EventID": event_id, "Channel": "Security", "Computer": "lab",
                       "EventRecordID": record_id, "TimeCreated": "2026-11-09T00:00:00Z",
                       "Provider": "Microsoft-Windows-Security-Auditing"}, "EventData": {}}


def test_valid_metadata(tmp_path):
    path = tmp_path / "events.jsonl"
    path.write_text("\n".join(json.dumps(event(i, 4672 if i % 2 else 4624))
                              for i in range(1, 4)) + "\n", encoding="utf-8")
    result = module.validate(path)
    assert result["total"] == 3
    assert result["duplicate_record_keys"] == 0
    assert result["out_of_order_records"] == 0


def test_duplicate_and_out_of_order(tmp_path):
    path = tmp_path / "events.jsonl"
    path.write_text("\n".join(json.dumps(event(i)) for i in (3, 2, 2)) + "\n")
    result = module.validate(path)
    assert result["duplicate_record_keys"] == 1
    assert result["out_of_order_records"] == 2


def test_rejects_sensitive_fields(tmp_path):
    path = tmp_path / "events.jsonl"
    item = event()
    item["EventData"]["TargetUserName"] = "secret"
    path.write_text(json.dumps(item) + "\n")
    with pytest.raises(ValueError, match="sensitive"):
        module.validate(path)


def test_rejects_unexpected_event_id(tmp_path):
    path = tmp_path / "events.jsonl"
    path.write_text(json.dumps(event(event_id=5379)) + "\n")
    with pytest.raises(ValueError, match="EventID"):
        module.validate(path)
