"""Offline validation of metadata-only Windows Security JSONL exports.

No credentials, network access, database connection, or production services.
Usage: python tools/windows/validate_export.py [path-to-jsonl]
"""
from __future__ import annotations

import argparse
import collections
import json
import os
from pathlib import Path

ALLOWED_IDS = {4624, 4625, 4672, 4688, 4720, 1102}
SYSTEM_KEYS = {"EventID", "Channel", "Computer", "EventRecordID", "TimeCreated", "Provider"}


def validate(path: Path) -> dict:
    if not path.is_file():
        raise ValueError("Export file does not exist")
    counts: collections.Counter[int] = collections.Counter()
    seen: set[tuple[str, str, int]] = set()
    duplicates = 0
    last_id: dict[tuple[str, str], int] = {}
    out_of_order = 0
    with path.open("r", encoding="utf-8-sig") as handle:
        for line_no, line in enumerate(handle, 1):
            if not line.strip():
                raise ValueError(f"Blank line at {line_no}")
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON at line {line_no}") from exc
            if not isinstance(obj, dict) or set(obj) != {"System", "EventData"}:
                raise ValueError(f"Unexpected top-level fields at line {line_no}")
            system = obj["System"]
            if not isinstance(system, dict) or set(system) != SYSTEM_KEYS or obj["EventData"] != {}:
                raise ValueError(f"Unexpected or sensitive fields at line {line_no}")
            event_id = system["EventID"]
            record_id = system["EventRecordID"]
            if type(event_id) is not int or event_id not in ALLOWED_IDS:
                raise ValueError(f"Unexpected EventID at line {line_no}")
            if type(record_id) is not int or record_id <= 0:
                raise ValueError(f"Invalid EventRecordID at line {line_no}")
            if system["Channel"] != "Security" or not all(
                isinstance(system[key], str) and system[key]
                for key in ("Computer", "TimeCreated", "Provider")
            ):
                raise ValueError(f"Invalid system metadata at line {line_no}")
            source = (system["Computer"], system["Channel"])
            key = (*source, record_id)
            if key in seen:
                duplicates += 1
            seen.add(key)
            if source in last_id and record_id <= last_id[source]:
                out_of_order += 1
            last_id[source] = record_id
            counts[event_id] += 1
    return {
        "total": sum(counts.values()),
        "by_event_id": dict(sorted(counts.items())),
        "duplicate_record_keys": duplicates,
        "out_of_order_records": out_of_order,
        "distinct_sources": len(last_id),
    }


def main() -> int:
    default = Path(os.environ.get("LOCALAPPDATA", ".")) / "AEGIS-AI" / "windows-events.jsonl"
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", nargs="?", type=Path, default=default)
    args = parser.parse_args()
    try:
        summary = validate(args.path)
    except (OSError, ValueError) as exc:
        parser.exit(1, f"Validation failed: {exc}\n")
    print(json.dumps(summary, indent=2))
    if summary["duplicate_record_keys"] or summary["out_of_order_records"]:
        print("Warning: duplicate or out-of-order records detected; do not ingest yet.")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
