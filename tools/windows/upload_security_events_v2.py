"""Experimental v2 HTTPS sender primitive; no CLI or automatic upload.

The caller must supply a verified, persisted source epoch and an already
validated homogeneous batch. This module never reads or writes v1 checkpoints.
"""
from __future__ import annotations

import json
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

from source_epoch_contract import validate_epoch_batch
from upload_security_events import MAX_BATCH, MAX_BYTES


def build_envelope(device_id: str, source_epoch: str, events: list[dict]) -> dict:
    envelope = {
        "protocol_version": 2, "device_id": device_id,
        "channel": "Security", "source_epoch": source_epoch,
        "events": events,
    }
    validate_epoch_batch(envelope)
    return envelope


def send_epoch_batch(endpoint: str, token: str, envelope: dict) -> int:
    """Send a validated v2 batch over verified HTTPS; return acknowledged ID.

    This is intentionally not exposed through an unattended command.
    """
    _, events = validate_epoch_batch(envelope)
    parsed = urllib.parse.urlsplit(endpoint)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username
            or parsed.password or parsed.fragment or parsed.port not in (None, 443)):
        raise ValueError("A valid HTTPS endpoint without embedded credentials is required")
    if not isinstance(token, str) or len(token) < 32 or any(c in token for c in "\r\n"):
        raise ValueError("Missing or invalid staging token")
    payload = json.dumps(envelope, separators=(",", ":")).encode("utf-8")
    if len(payload) > MAX_BYTES + 4096:
        raise ValueError("Payload exceeds maximum size")
    last = events[-1]["System"]["EventRecordID"]
    request = urllib.request.Request(
        endpoint, data=payload, method="POST",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None

    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ssl.create_default_context()), NoRedirect
    )
    # The free staging receiver can cold-start for 50+ seconds. A retry
    # reuses the identical envelope; the server's epoch-aware key makes
    # committed replays idempotent. No checkpoint is advanced here.
    for attempt in range(3):
        try:
            with opener.open(request, timeout=120) as response:
                if response.status != 200:
                    raise ValueError("Server did not acknowledge batch")
                raw = response.read(4097)
                if len(raw) > 4096:
                    raise ValueError("Oversized acknowledgement")
                ack = json.loads(raw)
            break
        except urllib.error.HTTPError as exc:
            if exc.code not in (429, 502, 503, 504) or attempt == 2:
                raise
        except (urllib.error.URLError, TimeoutError, socket.timeout):
            if attempt == 2:
                raise
        time.sleep(2 ** attempt)
    if (not isinstance(ack, dict) or set(ack) != {"accepted", "last_record_id"}
            or ack["accepted"] is not True
            or type(ack["last_record_id"]) is not int
            or ack["last_record_id"] != last):
        raise ValueError("Invalid or mismatched server acknowledgement")
    return last
