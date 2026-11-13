"""Read-only migration preflight regression tests."""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from plan_v2_migration import MigrationBlocked, inspect_export


def event(record):
    return {"System": {
        "EventID": 4624, "Channel": "Security", "Computer": "ci-host",
        "EventRecordID": record, "TimeCreated": "2026-11-13T00:00:00Z",
        "Provider": "Microsoft-Windows-Security-Auditing",
    }, "EventData": {}}


def setup(tmp_path, records=(10, 11), exported="11", uploaded=None):
    events = tmp_path / "events.jsonl"
    events.write_text("".join(json.dumps(event(x)) + "\n" for x in records),
                      encoding="utf-8")
    checkpoint = tmp_path / "export.checkpoint"
    checkpoint.write_text(exported, encoding="ascii")
    upload = tmp_path / "upload.checkpoint"
    if uploaded is not None:
        upload.write_text(uploaded, encoding="ascii")
    return events, checkpoint, upload


def test_valid_v1_file_is_still_not_automatically_migratable(tmp_path):
    paths = setup(tmp_path, uploaded="10")
    before = [p.read_bytes() for p in paths]
    report = inspect_export(*paths)
    assert report["events"] == 2
    assert report["export_checkpoint"] == 11
    assert report["upload_checkpoint"] == 10
    assert report["can_auto_migrate"] is False
    assert [p.read_bytes() for p in paths] == before


def test_missing_upload_checkpoint_is_not_modified(tmp_path):
    paths = setup(tmp_path)
    assert inspect_export(*paths)["upload_checkpoint"] == 0
    assert not paths[-1].exists()


@pytest.mark.parametrize("records,checkpoint", [
    ((10, 10), "10"),
    ((11, 10), "10"),
    ((10, 11), "12"),
])
def test_rejects_duplicates_regression_or_checkpoint_mismatch(tmp_path, records, checkpoint):
    with pytest.raises(MigrationBlocked):
        inspect_export(*setup(tmp_path, records=records, exported=checkpoint))


def test_rejects_upload_ahead_of_export(tmp_path):
    with pytest.raises(MigrationBlocked, match="exceeds"):
        inspect_export(*setup(tmp_path, uploaded="12"))


def test_rejects_private_event_fields(tmp_path):
    paths = setup(tmp_path)
    lines = paths[0].read_text().splitlines()
    invalid = json.loads(lines[1])
    invalid["EventData"] = {"TargetUserName": "private"}
    lines[1] = json.dumps(invalid)
    paths[0].write_text("\n".join(lines) + "\n")
    with pytest.raises(MigrationBlocked):
        inspect_export(*paths)
