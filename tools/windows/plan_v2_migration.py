"""Read-only v1-to-v2 migration preflight.

Does not assign epochs, change files, connect to a database or send telemetry.
A v1 JSONL file has no proof of log-instance continuity; the preflight
therefore never authorizes automatic migration.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from staging_receiver import validate


class MigrationBlocked(ValueError):
    pass


def inspect_export(events_path: Path, export_checkpoint: Path,
                   upload_checkpoint: Path) -> dict:
    """Return a metadata-only migration assessment; fail closed on corruption."""
    if any(path.is_symlink() for path in
           (events_path, export_checkpoint, upload_checkpoint)):
        raise MigrationBlocked("Symlinked migration input is not allowed")
    if not events_path.is_file():
        raise MigrationBlocked("Export JSONL file is missing")

    count = 0
    first = None
    last = 0
    computers = set()
    with events_path.open("r", encoding="utf-8-sig") as handle:
        for line in handle:
            if not line.strip():
                raise MigrationBlocked("Blank JSONL line")
            try:
                event = json.loads(line)
                _, checked = validate({"device_id": "preflight", "events": [event]})
                system = checked[0]["System"]
            except (ValueError, KeyError, TypeError) as exc:
                raise MigrationBlocked("Invalid event metadata in export") from exc
            record = system["EventRecordID"]
            if record <= last:
                raise MigrationBlocked("Duplicate or regressed record IDs in export")
            if first is None:
                first = record
            last = record
            computers.add(system["Computer"])
            count += 1

    if count == 0:
        raise MigrationBlocked("Export file contains no events")

    def read_id(path, *, required):
        if not path.exists():
            if required:
                raise MigrationBlocked("Export checkpoint missing")
            return 0
        try:
            raw = path.read_text(encoding="ascii").strip()
            if not raw.isdecimal():
                raise ValueError("Not decimal")
            return int(raw)
        except (OSError, ValueError) as exc:
            raise MigrationBlocked("Invalid checkpoint") from exc

    exported = read_id(export_checkpoint, required=True)
    uploaded = read_id(upload_checkpoint, required=False)
    if exported != last:
        raise MigrationBlocked("Export checkpoint differs from JSONL tail")
    if uploaded > exported:
        raise MigrationBlocked("Upload checkpoint exceeds export checkpoint")

    return {
        "events": count, "first_record_id": first, "last_record_id": last,
        "export_checkpoint": exported, "upload_checkpoint": uploaded,
        "distinct_computers": len(computers),
        "can_auto_migrate": False,
        "blocker": "v1 data has no verifiable source-epoch identity",
    }


def main():
    parser = argparse.ArgumentParser(description="AEGIS AI read-only v2 migration preflight")
    parser.add_argument("--events", type=Path, required=True)
    parser.add_argument("--export-checkpoint", type=Path, required=True)
    parser.add_argument("--upload-checkpoint", type=Path, required=True)
    args = parser.parse_args()
    result = inspect_export(args.events, args.export_checkpoint, args.upload_checkpoint)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
