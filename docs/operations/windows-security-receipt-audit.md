# Windows Security receipt audit

## Evidence and scope

On 2026-11-13, a read-only aggregate query against the explicitly named isolated
Supabase staging project confirmed **12 retained receipts, one device, one source
epoch**, with latest receipt at **17:25:18.053098 UTC**. No event payloads were
exported. This confirms persistence, not source completeness or detection.
No staging rows were inserted, modified, deleted, or replayed during this audit.
Production was not accessed. No deployment, continuous uploads, or paid resources
were enabled.

The v2 collector persists its scan cursor and metadata outbox together in SQLite.
Its default cycle does not send. The receiver commits before returning acceptance;
the primary key includes device, channel, source epoch, computer, and record ID.
Identical retries are accepted without extra rows; conflicting content aborts the
whole batch. Local acknowledgement failure preserves the outbox transaction for
restart and replay. Legacy v1 paths remain separate.

Staging has RLS enabled with the expected receiver-only SELECT and INSERT policies
bound to transaction-local `app.windows_device_id`. No UPDATE or DELETE policy is
present. The table owner has BYPASSRLS, so **the receiver must use the dedicated
non-owner login**. These policies isolate requests made by the trusted receiver;
a database credential holder can set the custom device context. They are not a
separate credential boundary between devices. The HTTP token is bound to one
configured device, checked before writes. Multi-device credential provisioning
requires additional design.

## Minimal hardening

Readiness previously accepted a superuser/owner connection because table grants
and receiver-role membership alone were sufficient. It now also requires RLS to
be enabled and rejects superusers, BYPASSRLS roles, table owners, and roles
inheriting owner privileges. This is a diagnostic check, not an upload gate;
deployment must still provision the documented restricted login. The status API
now rejects non-ASCII or newline-bearing configured tokens before opening its
upstream client. Neither change alters the collection or receipt protocol.

## Displaying the existing receipts

The application already mounts `WindowsSecurityStatus` in `ConnectorsView`, and
the API router includes `/api/v1/windows-security/status`. The panel polls only
when a tenant is resolved, uses a tenant-specific cache key, and reports failed
requests as unknown volume. No application component is missing in this branch.

The API process needs all three server-side settings:

- `AEGIS_WINDOWS_STAGING_TENANT_ID`: the authorized application tenant UUID.
- `AEGIS_WINDOWS_STAGING_STATUS_URL`: the existing HTTPS receiver status route,
  exactly `/v2/windows-security/status`, with no query or embedded credentials.
- `AEGIS_WINDOWS_STAGING_TOKEN`: the existing device token, kept server-side.

The current local process lacks these status settings. Hosted API configuration,
authenticated browser rendering of the actual receipts, and live receiver status
were not verified. Database persistence alone does not establish those paths.
No hosted settings were changed. A future approved configuration change should
verify the existing receiver GET status, then the authenticated API GET status,
then the Connectors panel for the authorized tenant. Verify another tenant sees
`configured:false`. This requires no upload or replay of the retained records.

## Detection and alerting integration design

The [local synthetic bridge follow-up](windows-security-synthetic-bridge.md)
records the isolated prototype, current validation, and remaining deployment
gates. The retained receipts remain disconnected.

The staging receiver deliberately has no Kafka publisher or alert promotion.
`services/connectors/app/connectors/windows_event.py` already normalizes Windows
envelopes and lifts System/EventData into `raw_event`. Its record-only external ID
is insufficient for this epoch-aware collector: distinct devices, hosts, or
epochs can reuse a record number. Do not connect the existing receiver to this
connector by URL; it provides receipt/status routes, not the connector's GET spool.

Proposed work, requiring a separately approved implementation and deployment:

1. Add an opt-in staging bridge with a server-provisioned device-to-tenant binding.
   Derive tenant from its authenticated service identity, never event JSON or a
   model. Keep the 12 retained records outside its eligibility set; start with
   labelled synthetic fixtures in a disposable pipeline.
2. Preserve receipt identities and payloads. Use a separate delivery ledger/outbox
   with retries and a canonical external ID derived unambiguously from the full
   `(device, channel, epoch, computer, record)` tuple. Include this string in the
   normalized payload: ingest's `generateEventID` uses connector, tenant, and
   external ID for stable identity. Test collision and crash/retry behavior.
3. Submit through the authenticated ingest handler and existing OCSF normalization,
   rather than writing alert rows directly. Fusion validates `ocsf_event` and the
   tenant UUID on `aisoc.raw_events`, evaluates detections/windowed rules, and
   persists matches through `_fuse_and_persist`. Leave response actions disabled.
4. Prove synthetic positive/negative paths through actual ingest, Kafka, fusion,
   and a disposable alert database. Assert replay creates no duplicate alert,
   wrong-tenant writes fail, and failed delivery remains retryable. Test promotion
   separately from corpus matching. Do not claim this pipeline was tested here.

Metadata-only events lack usernames, command lines, process image paths, and IP
addresses. Event ID predicates may be possible after mapping is verified, but
process-content rules and identity-based correlations cannot be claimed. Do not
fabricate missing fields or broaden collection to make a rule fire. A log-clear
event can also coincide with collector continuity loss; recovery must remain an
explicit operator decision.

## Verification

Synthetic tests cover actual WSGI HTTP and disposable PostgreSQL, non-owner RLS,
concurrent replay, conflict rollback, epoch reuse, storage failure, and a committed
receipt followed by failed SQLite acknowledgement and replay after restart.
The API tests use database-backed API-key authentication and controlled upstream
HTTP responses; dashboard tests use synthetic responses. They do not prove a live
browser-to-staging connection. Both new hardening checks were tested failing on
the original modules and passing with the fixes; restoring the original modules
again reproduced the failures.

Session results: 118 Windows tests, 6 authenticated API tests, and 7 dashboard
tests passed; frontend type checking and targeted lint/format checks passed.
Repository-wide lint reported 40 findings outside the changed Python files;
format checking reported 55 other files requiring formatting. The mypy baseline
gate ran with its recorded Python 3.11/mypy 2.4.0 versions but failed on Windows
path separator mismatches and unmanaged-scope accounting. These gates are not
reported as passing, and neither baselines nor scanner limits were changed.
