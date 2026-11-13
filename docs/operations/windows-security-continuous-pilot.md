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

## Ephemeral PostgreSQL CI validation

The `postgres-integration` GitHub Actions job launches a temporary
PostgreSQL 16 service container with a non-production test credential,
applies the isolated `windows_pilot` schema, and verifies transactional
acknowledgement, duplicate replay, and conflict rollback using psycopg 3.
The database is discarded after the job. It does not connect to Supabase,
use repository secrets, or deploy any receiver.

The tests are gated by `AEGIS_WINDOWS_TEST_DATABASE_URL` and are skipped
outside the dedicated CI job when no isolated database is configured.
A passing CI job establishes database-adapter behavior, **not** end-to-end
HTTPS delivery, device authentication at a public gateway, or dashboard
integration.

## Local HTTP-to-PostgreSQL harness

`tools/windows/staging_postgres_http_adapter.py` wires the existing
authenticated HTTP handler to `accept_batch_postgres` using a fresh psycopg
connection per request. It is intentionally bound to `127.0.0.1`, requires
`AEGIS_WINDOWS_TEST_DATABASE_URL`, `AEGIS_WINDOWS_STAGING_TOKEN`, and
`AEGIS_WINDOWS_DEVICE_ID`, and must only be used with an isolated test
database whose schema was applied separately. No database schema is
automatically created by the adapter.

This is a **local test harness without TLS**. Do not expose it publicly,
proxy it to the internet, point the uploader at it over HTTP, or configure
it with production credentials. The uploader's HTTPS requirement remains
unchanged. The handler tests verify that authentication and device binding
happen before the storage callback and that storage errors do not produce
successful acknowledgements.

## End-to-end local HTTP and PostgreSQL CI test

The dedicated PostgreSQL CI job now includes an integration test that
starts the bounded loopback HTTP adapter with a PostgreSQL persistence
callback and exercises bearer authentication, device spoof rejection,
successful acknowledgement after commit, idempotent HTTP replay, and
conflicting replay rejection. It verifies the committed database rows
directly afterward. This uses only synthetic test metadata and an ephemeral
CI PostgreSQL container. It is not a remote HTTPS test and does not access
real Windows Security logs or the production database.

## Security log reset: protocol migration required

The current sender checkpoint and server primary key are based on Windows
`EventRecordID`. That number can restart after the Security log is cleared.
A regression check on the exporter catches some resets but cannot reliably
detect a reset if new records have already exceeded the previous checkpoint.
**Do not automatically reset either checkpoint or delete the event file.**

Before enabling unattended remote ingestion, introduce a stable, explicit
`source_epoch` identifier across exporter, local event file, sender envelope,
receiver validation, and PostgreSQL primary key. The epoch must change on
verified log recreation/reset, persist across ordinary restarts, and be
bound to the authenticated device and channel. A transition needs a safe
migration for existing checkpoint and JSONL files, a documented manual
recovery path for ambiguous histories, and tests for reset/reuse, interrupted
writes, replay, and restart continuity. An arbitrary epoch generated on
each invocation would **not** be safe.

This remains a deployment blocker. Current code intentionally fails closed
for obvious record-ID regressions and does not claim to solve log resets.

## Source epoch v2 contract (experimental; not connected)

`source_epoch_contract.py` validates a versioned envelope containing
`protocol_version: 2`, `device_id`, `channel: Security`, a lowercase
32-hex-character `source_epoch`, and the same strict allowlisted event
metadata. `staging_postgres_epoch_schema.sql` defines a **separate**
`security_events_v2` table whose primary key includes the epoch.

These files do not mint epochs, detect log resets, change exporter JSONL
format, change checkpoints, accept remote v2 requests, or migrate v1 data.
The source epoch must be derived and persisted by a future continuity
manager that can fail closed when a reset cannot be verified. The
32-hex-character format is a transport identifier, not evidence of
continuity by itself. Existing local telemetry remains v1 and untouched.

## Fail-closed continuity state (not connected)

`source_continuity.py` now validates a separately persisted v2 source
identity and an externally supplied trusted log-instance marker. It rejects
missing/corrupt state, a changed marker, record-ID regression, and accidental
overwriting of an existing epoch. Its state is exclusive-create only; it
does not update the exporter or upload checkpoints.

**Important limitation:** The code does not yet obtain or authenticate a
stable Windows Security log-instance marker. A caller-provided marker is
not proof of log continuity. Until a trustworthy marker and an explicit
migration/recovery procedure exist, this module is a tested contract rather
than a reliable log-reset detector. The existing v1 collector remains
unchanged, and unattended remote ingestion remains blocked.

## Experimental v2 PostgreSQL ingestion

`staging_postgres_epoch_receiver.py` now implements atomic v2 batch
persistence into `windows_pilot.security_events_v2`. It scopes event
identity to device, channel, source epoch, computer, and record ID.
Identical replays are idempotent; conflicting replays abort the whole
transaction. The existing PostgreSQL CI job covers reused record IDs
across two epochs and rollback after a late conflict.

This is a **separate, unmounted v2 receiver**, not an enabled endpoint.
A trustworthy Windows log-instance marker, durable epoch lifecycle,
local-file/checkpoint migration, and authenticated HTTPS hosting are
still required before unattended real-event uploads.

## Experimental v2 loopback HTTP path

`staging_postgres_epoch_http_adapter.py` binds the authenticated HTTP
handler to the v2 PostgreSQL receiver. It only listens on
`127.0.0.1`, requires the same isolated test database and bearer/device
environment settings as the v1 harness, and does not provide TLS.
The PostgreSQL CI integration suite submits synthetic v2 requests through
HTTP, tests token and device rejection, checks duplicate replay, and
verifies reused record IDs are separately stored under distinct epochs.

**Not deployable as a public endpoint:** This is a local integration harness.
It does not establish trustworthy Windows log-instance identification,
migrate existing checkpoints, provide a hardened HTTPS gateway, or
connect the dashboard. Do not use production credentials.

## Experimental v2 HTTPS sender primitive

`upload_security_events_v2.py` provides a separately importable
`build_envelope` and `send_epoch_batch` implementation. It validates
v2 source-epoch envelopes, enforces standard-port verified HTTPS, rejects
redirects, and requires an exact server acknowledgement. Its contract
checks run in the Windows pilot CI workflow.

There is deliberately **no v2 CLI or scheduled upload**. The primitive
does not generate an epoch, access local JSONL or checkpoint files,
or enable network transfer on its own. Real migration requires a trusted
Windows source-instance identity, persisted epoch management, a safe
checkpoint transition, and separately approved staging HTTPS hosting.

## Read-only v1 to v2 migration assessment

`plan_v2_migration.py` inspects an existing metadata-only JSONL export
and its export/upload checkpoints without writing files or contacting
the network. It rejects malformed metadata, duplicate or regressed
record IDs, export-tail mismatch, and upload checkpoint ahead of export.
It reports only record counts, record-ID boundaries, checkpoint values,
and the number of distinct computers; it does not print event payloads.

A valid v1 export is **not proof** of a single log-instance epoch.
Accordingly the assessment always returns `can_auto_migrate: false`.
Do not generate a new epoch and reinterpret historical v1 records as
verified v2 data. Existing checkpoint files must not be overwritten.
A separately reviewed continuity source and manual recovery procedure
remain required before any real v2 sender activation.
