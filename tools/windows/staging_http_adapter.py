"""Loopback-only HTTP test adapter for the Windows staging receiver.

Never expose this prototype to public networks. TLS and real device identity
must be supplied by a reviewed staging gateway before any remote ingestion.
"""
from __future__ import annotations

import argparse
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from staging_receiver import MAX_REQUEST_BYTES, InvalidBatch, accept_batch, authorize


def handler_factory(database: Path, expected_token: str, expected_device_id: str = "test-device"):
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            if self.path != "/v1/windows-security/events":
                self.send_error(404)
                return
            supplied = self.headers.get("Authorization", "")
            if not supplied.startswith("Bearer "):
                self.send_error(401)
                return
            try:
                authorize(supplied[7:], expected_token)
            except PermissionError:
                self.send_error(401)
                return
            if self.headers.get("Content-Type", "").split(";")[0].strip().lower() != "application/json":
                self.send_error(415)
                return
            raw_length = self.headers.get("Content-Length")
            if not raw_length or not raw_length.isdecimal():
                self.send_error(411)
                return
            length = int(raw_length)
            if length < 1 or length > MAX_REQUEST_BYTES:
                self.send_error(413)
                return
            try:
                raw = self.rfile.read(length)
                if len(raw) != length:
                    raise InvalidBatch("Truncated request")
                payload = json.loads(raw)
                if not isinstance(payload, dict) or payload.get("device_id") != expected_device_id:
                    raise PermissionError("Device identity does not match credential")
                result = accept_batch(database, payload)
            except PermissionError:
                self.send_error(403)
                return
            except (InvalidBatch, ValueError, UnicodeDecodeError, json.JSONDecodeError):
                self.send_error(400)
                return
            except Exception:
                self.send_error(500)
                return
            response = json.dumps(result, separators=(",", ":")).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(response)))
            self.end_headers()
            self.wfile.write(response)

        def log_message(self, format, *args):
            # Avoid logging tokens or event payloads.
            return

    return Handler


def main():
    parser = argparse.ArgumentParser(description="AEGIS AI loopback-only Windows receiver test adapter")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--database", type=Path, default=Path("windows-security-staging.sqlite"))
    args = parser.parse_args()
    token = os.getenv("AEGIS_WINDOWS_STAGING_TOKEN", "")
    device_id = os.getenv("AEGIS_WINDOWS_DEVICE_ID", "")
    if len(token) < 32:
        raise SystemExit("Set AEGIS_WINDOWS_STAGING_TOKEN to a random token of at least 32 characters")
    if not device_id or len(device_id) > 128 or not all(c.isascii() and (c.isalnum() or c in "._-") for c in device_id):
        raise SystemExit("Set a valid AEGIS_WINDOWS_DEVICE_ID bound to this token")
    if not 1 <= args.port <= 65535:
        raise SystemExit("Invalid port")
    server = ThreadingHTTPServer(("127.0.0.1", args.port), handler_factory(args.database, token, device_id))
    print(f"Loopback-only receiver listening on 127.0.0.1:{args.port}; no TLS, do not expose externally")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
