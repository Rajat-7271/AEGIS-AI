# Windows Security continuous collection — isolated pilot

This is a **local-only** collection experiment, not a cloud ingestion integration.
It never sends Windows events to AEGIS AI or any third-party endpoint.

## Test on Windows

From the repository root, using an account permitted to read the Security log:

```powershell
powershell.exe -NoProfile -File .\tools\windows\watch-security-events.ps1 -IntervalSeconds 30 -MaxEvents 100 -MaxCycles 3
python .\tools\windows\validate_export.py
```

The first invocation looks back 24 hours. Subsequent invocations resume from the
local EventRecordID checkpoint. The exporter appends only metadata for an
allowlist of Security event IDs; it deliberately omits event messages, usernames,
command lines and credentials.

Default local files:

- `%LOCALAPPDATA%\AEGIS-AI\windows-events.jsonl`
- `%LOCALAPPDATA%\AEGIS-AI\windows-events.checkpoint`

The wrapper exits after `MaxCycles` polls, or on Ctrl+C. An exporter error
terminates collection; **do not delete or advance the checkpoint** to bypass
a safety stop. Inspect the file and cause first. The export checkpoint means
"persisted locally", **not** "accepted by a server".

## Not yet implemented

- A staging ingestion endpoint and device authentication.
- A sender with bounded batches, TLS verification, server acknowledgements,
  retry/backoff and an independent *upload* checkpoint.
- Server-side idempotency by host/channel/record ID plus an explicit log-reset
  epoch policy.
- Dashboard confirmation, lag metrics, offline replay and failure tests.

Do not expose the JSONL file on a public HTTP endpoint or place bearer tokens
in scripts. A secure sender must advance its upload checkpoint **only after**
the server acknowledges durable acceptance. Keep the local exporter checkpoint
separate to prevent loss during network outages.

No production deployment or merge is authorized by this pilot.

## Sender dry run (no network)

After a successful local export:

```powershell
python .\tools\windows\upload_security_events.py
python -m pytest -q .\tools\windows\test_upload_security_events.py
```

The uploader processes at most 100 pending events per invocation and keeps a
**separate** `windows-events.upload.checkpoint` file. Dry runs do not modify
this checkpoint. It refuses extra event fields to avoid transmitting personal
or credential data.

**Do not use `--send` yet.** The staging receiver is not implemented.
When it exists, it must authenticate per-device credentials, validate the
allowlist and batch size, durably persist with idempotent record keys, then
return HTTP 200 with `{"accepted":true,"last_record_id":N}` only after
durable acceptance. No public production endpoint is authorized.

## Receiver core (draft, not deployed)

`tools/windows/staging_receiver.py` provides a standalone, dependency-free
batch validator and transactional SQLite persistence for a staging prototype.
It validates metadata-only records, rejects conflicting replays, and returns
the sender's acknowledgement shape only after a database commit. It also
provides a constant-time token comparison helper for a future HTTP adapter.

```powershell
python -m pytest -q .\tools\windows\test_staging_receiver.py .\tools\windows\test_upload_security_events.py
```

**There is no HTTP listener, HTTPS termination, credential provisioning,
dashboard integration, or deployed staging service yet.** Do not enable
`--send`. Before exposing any route, add a secure authenticated adapter,
per-device token management, request-size limits, rate limiting, TLS,
retention policy, monitoring, source-epoch handling, and a reviewed
production-grade database implementation. SQLite is used only to prove the
durable acknowledgement and replay contract locally.

## Loopback HTTP integration adapter

`tools/windows/staging_http_adapter.py` is a **local-only** HTTP adapter
bound to `127.0.0.1`. It is not a deployable HTTPS service and must never
be exposed to the Internet. It demonstrates bearer authentication, request
limits, metadata validation, transactional persistence, and acknowledgements
using the SQLite prototype.

Run the tests (no credentials or external services needed):

```powershell
python -m pytest -q .\tools\windows\test_staging_http_adapter.py .\tools\windows\test_staging_receiver.py .\tools\windows\test_upload_security_events.py
```

The sender intentionally requires HTTPS and cannot connect to this
plain-HTTP adapter; do not weaken that protection. A later staging-only TLS
gateway and server-side device identity validation are prerequisites for
live PC-to-cloud upload. The current receiver's token comparison helper
does not yet bind a token to a specific `device_id`.
