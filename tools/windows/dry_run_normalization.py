"""Offline bridge from validated Windows JSONL into the connector's normalized shape.

No network calls, credentials, or writes. Prints a summary only. The normalizer
is the same WindowsEventConnector used by the connector service.

From repo root:
  python tools/windows/dry_run_normalization.py
Requires connector-service dependencies (httpx, structlog) installed.
"""
from __future__ import annotations

import collections
import importlib.util
import types
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
# Import just the Windows connector, bypassing the package registry in
# app.connectors.__init__ (which imports every vendor connector).
CONNECTORS = ROOT / "services" / "connectors" / "app" / "connectors"
app_package = types.ModuleType("app")
app_package.__path__ = [str(CONNECTORS.parent)]
connector_package = types.ModuleType("app.connectors")
connector_package.__path__ = [str(CONNECTORS)]
sys.modules["app"] = app_package
sys.modules["app.connectors"] = connector_package


def _load_connector_module(name: str):
    full_name = f"app.connectors.{name}"
    spec = importlib.util.spec_from_file_location(full_name, CONNECTORS / f"{name}.py")
    if spec is None or spec.loader is None:
        raise ImportError(f"Unable to load {full_name}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[full_name] = module
    spec.loader.exec_module(module)
    return module


_load_connector_module("base")
WindowsEventConnector = _load_connector_module("windows_event").WindowsEventConnector
from validate_export import validate  # noqa: E402


def dry_run(path: Path) -> dict:
    report = validate(path)
    if report["duplicate_record_keys"] or report["out_of_order_records"]:
        raise ValueError("Export has duplicate or out-of-order records")
    connector = WindowsEventConnector("https://unused.invalid/spool", "unused")
    by_severity: collections.Counter[str] = collections.Counter()
    by_event_type: collections.Counter[str] = collections.Counter()
    with path.open(encoding="utf-8-sig") as handle:
        for line in handle:
            normalized = connector.normalize(json.loads(line))
            if not normalized["external_id"] or not normalized["created_at"]:
                raise ValueError("Normalizer lost event identity or timestamp")
            by_severity[normalized["severity"]] += 1
            by_event_type[normalized["event_type"]] += 1
    return {
        "normalized": report["total"],
        "by_severity": dict(sorted(by_severity.items())),
        "by_event_type": dict(sorted(by_event_type.items())),
        "network_requests": 0,
        "backend_ingestion": "not attempted",
    }


def main() -> int:
    default = Path(os.environ.get("LOCALAPPDATA", ".")) / "AEGIS-AI" / "windows-events.jsonl"
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else default
    try:
        print(json.dumps(dry_run(path), indent=2))
    except (OSError, ValueError) as exc:
        print(f"Dry run failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
