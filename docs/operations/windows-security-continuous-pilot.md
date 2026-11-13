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
