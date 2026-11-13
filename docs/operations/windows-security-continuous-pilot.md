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

## Device identity binding

The loopback adapter requires `AEGIS_WINDOWS_DEVICE_ID` and
`AEGIS_WINDOWS_STAGING_TOKEN` to be configured together. An authenticated
request claiming a different device ID is rejected with HTTP 403 before
persistence. This is a single-device prototype; staging deployment still
needs securely provisioned per-device credentials, TLS, and an appropriate
persistent database. Never commit tokens or print them in logs.

## Additional sender hardening

The sender now rejects invalid device identifiers, batches larger than 100,
and HTTPS URLs using nonstandard ports. The offline tests also exercise
successful and mismatched acknowledgements without contacting a server.
These checks do **not** establish that a cloud endpoint is ready. Keep
`--send` disabled until a reviewed staging HTTPS receiver and credentials
are provisioned.

## Staging deployment gate

Do not deploy the loopback HTTP adapter as a public service. The current
implementation is a **protocol test harness**, not an internet-facing
ingestion API. Before enabling remote upload, the following must be reviewed
and tested together:

1. Dedicated staging hostname and TLS termination, with redirects disabled.
2. Per-device token issuance, secure storage, rotation, revocation, and
   server-side binding of credential to device identity.
3. A persistent staging database with explicit retention and backup policy;
   verify transactional commit before acknowledgement.
4. Request rate limiting, body-size and connection timeouts, health checks,
   and safe operational logs without credentials or event payloads.
5. Source epoch or boot/log-reset identity to prevent record-ID collisions
   after Security log recreation.
6. Integration tests for lost responses, repeated batches, concurrent
   requests, database failure, and interrupted checkpoint writes.
7. Explicit approval before any staging deployment. Production and existing
   public endpoints are out of scope.

The local sender continues to default to dry run, and now checks the shape
of historical rows even when their record IDs are below its separate upload
checkpoint. This protects against silently overlooking modified event files.

## Automated validation

The dedicated `.github/workflows/windows-security-pilot.yml` workflow runs
the Python sender, receiver, and HTTP adapter tests automatically for changes
under `tools/windows/` and for workflow edits. It runs without staging
credentials or Windows Security log access. This replaces repeated manual
invocations of the offline tests; real Windows collection and remote staging
integration still require separate milestone validation.

The receiver suite now covers overlapping retries and rejection of a batch
containing a later private-field event. Neither test requires real telemetry.

## Loopback adapter request throttling

The prototype adapter now limits authenticated requests to 60 per rolling
minute by default, returning HTTP 429 when exceeded. The limit is scoped to
the adapter process and resets on restart. It is **not** a replacement for
staging gateway IP/device quotas, connection limits, distributed rate limits,
or network-layer denial-of-service protection. Unauthorized requests are
rejected before consuming the authenticated request quota.

## Idle connection safety in the local harness

The loopback receiver uses a bounded server class with a ten-second socket
timeout, a 16-connection listen backlog, and daemon request-handler threads.
This reduces the impact of stalled local clients and makes shutdown more
predictable. It does not impose a strict cap on simultaneously running
handlers and is **not** a public-network security boundary. A real staging
deployment must enforce connection limits and timeouts at its HTTPS gateway.

## Isolated PostgreSQL staging storage (not deployed)

`tools/windows/staging_postgres_schema.sql` defines a dedicated
`windows_pilot.security_events` table with a composite idempotency key.
`tools/windows/staging_postgres_receiver.py` provides a transactional
persistence function: validate the allowlisted metadata, insert events,
compare conflicting replays, commit, and only then return the final record
acknowledgement. It is **not wired to a public HTTPS route**.

The PostgreSQL adapter expects a psycopg 3 connection supplied by a
staging-only service; importing the module does not open a database
connection. Its offline tests simulate transaction rollback and replay.
Actual PostgreSQL integration tests, staging credentials, database role
permissions, and connection management remain outstanding.

**Do not apply this SQL to the production Supabase database.** Provision
an isolated staging database and least-privilege service role only after
explicit staging deployment approval. The existing record identity does
not yet include a log-reset/source epoch; production-grade ingestion
requires this before unrestricted use.
