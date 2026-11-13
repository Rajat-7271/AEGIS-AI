"""Staging-only Windows event uploader. No upload without explicit --send.

Protocol: POST JSON {"device_id":..., "events":[...]} over verified HTTPS.
A successful response must contain {"accepted": true, "last_record_id": N}
where N exactly equals the final submitted record ID. This is a proposed
staging contract; the receiving endpoint has NOT yet been implemented.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import ssl
import tempfile
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_DIR = Path(os.environ.get("LOCALAPPDATA", ".")) / "AEGIS-AI"
MAX_BATCH = 100
MAX_BYTES = 256_000


def load_batch(path: Path, acknowledged: int, limit: int = MAX_BATCH) -> list[dict]:
    batch: list[dict] = []
    size = 0
    previous = acknowledged
    with path.open(encoding="utf-8-sig") as handle:
        for line in handle:
            if not line.strip():
                raise ValueError("Blank event line")
            event = json.loads(line)
            system = event.get("System")
            if not isinstance(system, dict):
                raise ValueError("Missing System metadata")
            record = system.get("EventRecordID")
            if type(record) is not int or record < 1:
                raise ValueError("Invalid record ID")
            if record <= acknowledged:
                continue
            if record <= previous:
                raise ValueError("Out-of-order or duplicate unacknowledged record")
            if system.get("Channel") != "Security" or system.get("EventID") not in (4624, 4625, 4672, 4688, 4720, 1102):
                raise ValueError("Unexpected event channel or ID")
            if set(event) != {"System", "EventData"} or event.get("EventData") != {}:
                raise ValueError("Refusing to upload unexpected event fields")
            if set(system) != {"EventID", "Channel", "Computer", "EventRecordID", "TimeCreated", "Provider"}:
                raise ValueError("Refusing to upload unexpected System fields")
            encoded = json.dumps(event, separators=(",", ":")).encode("utf-8")
            if len(encoded) > MAX_BYTES:
                raise ValueError("Single event exceeds maximum payload")
            if batch and (len(batch) >= limit or size + len(encoded) > MAX_BYTES):
                break
            batch.append(event)
            size += len(encoded)
            previous = record
    return batch


def read_checkpoint(path: Path) -> int:
    if not path.exists():
        return 0
    raw = path.read_text(encoding="ascii").strip()
    if not raw.isdecimal():
        raise ValueError("Invalid upload checkpoint")
    return int(raw)


def save_checkpoint(path: Path, record: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    name = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="ascii", dir=path.parent, delete=False) as handle:
            name = handle.name
            handle.write(str(record))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(name, path)
    finally:
        if name and os.path.exists(name):
            os.unlink(name)


def send_batch(endpoint: str, token: str, device_id: str, batch: list[dict]) -> int:
    parsed = urllib.parse.urlsplit(endpoint)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.fragment or parsed.port not in (None, 443):
        raise ValueError("A valid HTTPS endpoint without embedded credentials is required")
    if not token or not device_id or len(device_id) > 128 or not all(c.isascii() and (c.isalnum() or c in "._-") for c in device_id):
        raise ValueError("Missing token or invalid device identifier")
    if not 1 <= len(batch) <= MAX_BATCH:
        raise ValueError("Invalid upload batch size")
    last = batch[-1]["System"]["EventRecordID"]
    payload = json.dumps({"device_id": device_id, "events": batch}, separators=(",", ":")).encode()
    if len(payload) > MAX_BYTES + 4096:
        raise ValueError("Payload exceeds maximum size")
    request = urllib.request.Request(
        endpoint, data=payload, method="POST",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    # Do not follow redirects: authorization headers must not be forwarded.
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None

    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ssl.create_default_context()), NoRedirect
    )
    with opener.open(request, timeout=15) as response:
        if response.status != 200:
            raise ValueError("Server did not acknowledge batch")
        raw = response.read(4097)
        if len(raw) > 4096:
            raise ValueError("Oversized acknowledgement")
        ack = json.loads(raw)
    if not isinstance(ack, dict) or ack.get("accepted") is not True or type(ack.get("last_record_id")) is not int or ack["last_record_id"] != last:
        raise ValueError("Invalid or mismatched server acknowledgement")
    return last


def main() -> None:
    parser = argparse.ArgumentParser(description="AEGIS AI staging Windows uploader (dry-run by default)")
    parser.add_argument("--events", type=Path, default=DEFAULT_DIR / "windows-events.jsonl")
    parser.add_argument("--upload-checkpoint", type=Path, default=DEFAULT_DIR / "windows-events.upload.checkpoint")
    parser.add_argument("--send", action="store_true", help="Explicitly enable HTTPS upload")
    parser.add_argument("--endpoint", default=os.getenv("AEGIS_WINDOWS_STAGING_URL", ""))
    parser.add_argument("--device-id", default=os.getenv("AEGIS_WINDOWS_DEVICE_ID", ""))
    args = parser.parse_args()
    checkpoint = read_checkpoint(args.upload_checkpoint)
    batch = load_batch(args.events, checkpoint)
    if not batch:
        print("No pending events")
        return
    last = batch[-1]["System"]["EventRecordID"]
    if not args.send:
        print(f"DRY RUN: {len(batch)} pending metadata-only events; last record {last}; no network request")
        return
    token = os.getenv("AEGIS_WINDOWS_STAGING_TOKEN", "")
    acknowledged = send_batch(args.endpoint, token, args.device_id, batch)
    save_checkpoint(args.upload_checkpoint, acknowledged)
    print(f"Server acknowledged {len(batch)} events; upload checkpoint {acknowledged}")


if __name__ == "__main__":
    main()
