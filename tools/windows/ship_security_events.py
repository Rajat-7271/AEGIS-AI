"""Opt-in Windows Security JSONL shipper for AEGIS AI.

Reads metadata-only output from export-security-events.ps1. Never enables live
sending unless --send is explicitly supplied. For live use, requires HTTPS,
a tenant-scoped token and a real tenant/connector UUID. This is a bounded
batch sender, not a Windows Event subscription or service.

The cursor advances only after a full batch acknowledgement. On ambiguous
delivery it retries the same batch on the next run; backend idempotency must
be verified before enabling production.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import importlib.util
import types
import os
import sys
import uuid
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[2]
# Load only the Windows connector and its base module. Importing the package
# initializer loads unrelated cloud connectors and their optional dependencies.
CONNECTORS = ROOT / "services" / "connectors" / "app" / "connectors"
app = types.ModuleType("app")
app.__path__ = [str(CONNECTORS.parent)]
package = types.ModuleType("app.connectors")
package.__path__ = [str(CONNECTORS)]
sys.modules["app"] = app
sys.modules["app.connectors"] = package


def load_connector_module(name: str):
    fullname = f"app.connectors.{name}"
    spec = importlib.util.spec_from_file_location(fullname, CONNECTORS / f"{name}.py")
    if spec is None or spec.loader is None:
        raise ImportError(f"Unable to load {fullname}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[fullname] = module
    spec.loader.exec_module(module)
    return module


load_connector_module("base")
WindowsEventConnector = load_connector_module("windows_event").WindowsEventConnector


def read_batch(path: Path, cursor: int, limit: int) -> tuple[list[dict], int]:
    if not path.is_file():
        raise ValueError("JSONL export does not exist")
    events = []
    last_line = cursor
    observed_lines = 0
    with path.open("r", encoding="utf-8-sig") as stream:
        for line_no, line in enumerate(stream, 1):
            observed_lines = line_no
            if line_no <= cursor:
                continue
            if not line.strip():
                raise ValueError(f"Blank JSONL line {line_no}")
            raw = json.loads(line)
            if set(raw) != {"System", "EventData"} or raw["EventData"] != {}:
                raise ValueError(f"Unexpected export structure at line {line_no}")
            system = raw["System"]
            if not isinstance(system, dict) or set(system) != {
                "EventID", "Channel", "Computer", "EventRecordID", "TimeCreated", "Provider"
            }:
                raise ValueError(f"Unexpected Security metadata at line {line_no}")
            if system["Channel"] != "Security" or type(system["EventRecordID"]) is not int:
                raise ValueError(f"Invalid Security metadata at line {line_no}")
            if type(system["EventID"]) is not int or system["EventID"] not in {
                4624, 4625, 4672, 4688, 4720, 1102
            }:
                raise ValueError(f"Unexpected EventID at line {line_no}")
            if not all(isinstance(system[k], str) and system[k] for k in (
                "Computer", "TimeCreated", "Provider"
            )):
                raise ValueError(f"Missing Security metadata at line {line_no}")
            events.append(raw)
            last_line = line_no
            if len(events) == limit:
                break
    if not events and cursor > observed_lines:
        raise ValueError("JSONL export is shorter than saved shipper cursor; refusing to skip events")
    return events, last_line


def save_cursor(path: Path, cursor: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    with tmp.open("w", encoding="utf-8") as handle:
        handle.write(str(cursor))
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, path)


async def send_batch(url: str, token: str, tenant: str, connector: str, events: list[dict]) -> dict:
    async with httpx.AsyncClient(timeout=30, trust_env=False) as client:
        response = await client.post(
            url.rstrip("/") + "/v1/ingest/batch",
            headers={"Authorization": "Bearer " + token, "X-Tenant-ID": tenant},
            json={"connector_id": connector, "connector_type": "windows_event",
                  "source_format": "raw_json", "events": events},
        )
        response.raise_for_status()
        ack = response.json()
        if not isinstance(ack, dict) or type(ack.get("accepted")) is not int or (
            ack["accepted"] != len(events) or type(ack.get("rejected")) is not int
            or ack["rejected"] != 0
        ):
            raise RuntimeError("Incomplete ingestion acknowledgement; cursor unchanged")
        return ack


async def run(args: argparse.Namespace) -> None:
    cursor = 0
    if args.cursor.exists():
        text = args.cursor.read_text(encoding="utf-8").strip()
        if not text.isdecimal():
            raise ValueError("Invalid shipper cursor; refusing to continue")
        cursor = int(text)
    if not args.send:
        raw, _ = read_batch(args.input, cursor, args.limit)
        normalized = WindowsEventConnector("https://unused.invalid", "unused")
        events = [normalized.normalize(e) for e in raw]
        print(json.dumps({"mode": "dry-run", "events": len(events),
                          "cursor_unchanged": cursor, "network_requests": 0}))
        return

    url = args.url or ""
    token = os.getenv("AEGIS_WINDOWS_INGEST_TOKEN", "")
    if not url.startswith("https://") or not token.strip():
        raise ValueError("Sending requires HTTPS --url and AEGIS_WINDOWS_INGEST_TOKEN")
    tenant = str(uuid.UUID(args.tenant))
    connector = str(uuid.UUID(args.connector))
    normalized = WindowsEventConnector("https://unused.invalid", "unused")
    acknowledged = 0
    # Drain a bounded backlog each scheduled invocation, not just one batch.
    # Each batch is checkpointed only after full server acknowledgement.
    for _ in range(args.max_batches):
        raw, next_cursor = read_batch(args.input, cursor, args.limit)
        if not raw:
            break
        events = [normalized.normalize(e) for e in raw]
        await send_batch(url, token, tenant, connector, events)
        save_cursor(args.cursor, next_cursor)
        cursor = next_cursor
        acknowledged += len(events)
        if len(raw) < args.limit:
            break
    print(json.dumps({"mode": "send", "acknowledged": acknowledged,
                      "cursor": cursor}))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    default = Path(os.environ.get("LOCALAPPDATA", ".")) / "AEGIS-AI"
    parser.add_argument("--input", type=Path, default=default / "windows-events.jsonl")
    parser.add_argument("--cursor", type=Path, default=default / "windows-shipper.cursor")
    parser.add_argument("--limit", type=int, default=100)
    parser.add_argument("--send", action="store_true", help="Explicitly enable HTTPS transmission")
    parser.add_argument("--max-batches", type=int, default=5, help="Maximum acknowledged batches per run")
    parser.add_argument("--url", help="Approved staging ingest URL")
    parser.add_argument("--tenant", help="Tenant UUID")
    parser.add_argument("--connector", help="Connector UUID")
    args = parser.parse_args()
    if not 1 <= args.limit <= 500:
        parser.error("--limit must be between 1 and 500")
    if not 1 <= args.max_batches <= 20:
        parser.error("--max-batches must be between 1 and 20")
    try:
        asyncio.run(run(args))
    except (ValueError, OSError, json.JSONDecodeError, httpx.HTTPError, RuntimeError) as exc:
        parser.exit(1, f"Shipper stopped without advancing cursor: {type(exc).__name__}: {exc}\n")


if __name__ == "__main__":
    main()
