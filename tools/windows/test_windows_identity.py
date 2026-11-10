"""Offline Windows source-identity regression tests for staging readiness.

Run from repository root with connector dependencies installed:
  python tools/windows/test_windows_identity.py

Only synthetic events. No sockets, credentials, production services or real logs.
The Go UUID comparison models generateEventID; it is NOT a Go runtime test.
"""
from __future__ import annotations

import importlib.util
import json
import sys
import types
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CONNECTORS = ROOT / "services" / "connectors" / "app" / "connectors"
app = types.ModuleType("app")
app.__path__ = [str(CONNECTORS.parent)]
package = types.ModuleType("app.connectors")
package.__path__ = [str(CONNECTORS)]
sys.modules["app"] = app
sys.modules["app.connectors"] = package


def load(name: str):
    fullname = f"app.connectors.{name}"
    spec = importlib.util.spec_from_file_location(fullname, CONNECTORS / f"{name}.py")
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load {fullname}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[fullname] = module
    spec.loader.exec_module(module)
    return module


load("base")
WindowsEventConnector = load("windows_event").WindowsEventConnector


def event(host: str, channel: str, record_id: int, timestamp: str = "2026-11-10T10:00:00Z") -> dict:
    return {
        "System": {
            "EventID": 4624,
            "Channel": channel,
            "Computer": host,
            "EventRecordID": record_id,
            "TimeCreated": timestamp,
            "Provider": "Microsoft-Windows-Security-Auditing",
        },
        "EventData": {},
    }


def go_id_model(external_id: str, tenant: str, connector: str) -> str:
    # Mirrors normalizer.generateEventID's UUIDv5 / NameSpaceOID / SHA1 path.
    return str(uuid.uuid5(uuid.NAMESPACE_OID, f"{connector}:{tenant}:external_id={external_id}"))


def main() -> None:
    connector = WindowsEventConnector("https://unused.invalid/spool", "dummy")
    normalize = connector.normalize
    first = normalize(event("HOST-A", "Security", 42))
    replay = normalize(event("host-a", "security", 42))
    another_host = normalize(event("host-b", "Security", 42))
    another_channel = normalize(event("host-a", "OtherChannel", 42))
    another_record = normalize(event("host-a", "Security", 43))

    assert first["external_id"] == replay["external_id"], "Same source record changed identity"
    assert len({first["external_id"], another_host["external_id"],
                another_channel["external_id"], another_record["external_id"]}) == 4

    tenant_a = "11111111-1111-4111-8111-111111111111"
    tenant_b = "22222222-2222-4222-8222-222222222222"
    stable = go_id_model(first["external_id"], tenant_a, "windows_event")
    assert stable == go_id_model(replay["external_id"], tenant_a, "windows_event")
    assert stable != go_id_model(first["external_id"], tenant_b, "windows_event")
    assert stable != go_id_model(first["external_id"], tenant_a, "other_connector")

    # Known blocker: a Windows Security log clear can reuse EventRecordID.
    # Even with a different timestamp, the current source identity collides.
    after_clear = normalize(event("host-a", "Security", 42, "2026-11-11T10:00:00Z"))
    assert after_clear["external_id"] == first["external_id"], (
        "Source epoch semantics changed: revisit this regression and rollout gate"
    )
    # A trusted collector may explicitly assign a stable source epoch.
    # The same epoch must replay identically; a new epoch separates reused IDs.
    epoch_one = event("host-a", "Security", 42)
    epoch_one["SourceEpoch"] = "epoch-1"
    epoch_one_replay = event("host-a", "Security", 42, "2026-11-11T10:00:00Z")
    epoch_one_replay["SourceEpoch"] = "epoch-1"
    epoch_two = event("host-a", "Security", 42, "2026-11-11T10:00:00Z")
    epoch_two["SourceEpoch"] = "epoch-2"
    assert normalize(epoch_one)["external_id"] == normalize(epoch_one_replay)["external_id"]
    assert normalize(epoch_one)["external_id"] != normalize(epoch_two)["external_id"]
    assert normalize(epoch_one)["external_id"] != first["external_id"]

    print(json.dumps({
        "status": "passed",
        "same_record_replay_stable": True,
        "cross_host_channel_record_separated": True,
        "tenant_and_connector_model_separated": True,
        "log_clear_record_reuse_collision": True,
        "explicit_source_epoch_supported": True,
        "log_clear_policy": "BLOCKER: exporter does not yet persist trusted source epochs",
        "go_runtime_verified": False,
        "downstream_storage_verified": False,
        "network_requests": 0,
        "real_events_sent": 0,
    }, indent=2))


if __name__ == "__main__":
    main()
