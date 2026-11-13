# Windows Security local synthetic bridge

This follow-up to the receipt audit adds an isolated prototype, not a live
integration. No receipt table is read and none of the 12 retained staging receipts
is eligible. No production or staging access, hosted configuration change,
deployment, upload loop, alert insertion, or response action was performed.

## Dashboard readiness

The existing `ConnectorsView` mounts `WindowsSecurityStatus`. Its SWR key includes
the resolved tenant, polling runs every 30 seconds, and request errors show unknown
volume. Synthetic twelve-receipt rendering already exists. No dashboard or API
feature was missing in this audit, so their implementation is unchanged.

`GET /api/v1/windows-security/status` requires authenticated `connectors:read`.
The authenticated principal supplies the tenant. Another tenant receives
`configured:false` before any upstream request. Upstream responses are strictly
validated, redirects disabled, and failures return a generic 503 without tokens.
The response explicitly describes metadata receipts with detection disconnected.

These exact API-process variables are required; none is a browser/public setting:

| Variable | Requirement |
| --- | --- |
| `AEGIS_WINDOWS_STAGING_TENANT_ID` | Exact authorized application tenant UUID string |
| `AEGIS_WINDOWS_STAGING_STATUS_URL` | Existing HTTPS receiver URL on port 443 with exact path `/v2/windows-security/status`; no query, fragment or embedded credentials |
| `AEGIS_WINDOWS_STAGING_TOKEN` | Existing device bearer token, at least 32 ASCII characters, no CR/LF |

All three are absent from this session's process environment. The existing upload
endpoint variable is not a substitute for the status URL. Secret values were not
printed or changed. The historic 12-receipt aggregate was not queried again;
authenticated live rendering remains unverified.

## Prototype boundaries and behavior

`tools/windows/synthetic_detection_bridge.py` requires `enabled=True`, an explicit
private disposable SQLite path, and fixtures with `synthetic:true`. The batch
uses the existing strict v2 metadata validator. Device-to-tenant bindings and
connector UUIDs are supplied by the trusted test harness, never fixture JSON.
The ledger pins a device to one tenant for the experiment and filters delivery
by tenant and connector. This is local harness isolation, not a new authenticated
network service or a database credential boundary. Labels alone cannot prove
data provenance: never feed real records to this module.

The external ID is `windows-v2:` followed by compact JSON encoding of
`[device, channel, source_epoch, computer, record_id]`. JSON avoids delimiter
ambiguities. Raw metadata, lifted System fields, and the complete identity are
retained under `raw_event`; no absent usernames, commands or IPs are invented.
The envelope is marked synthetic and severity stays `info`; this prototype
does not assert a detection severity or create alerts.

An independent ledger atomically rejects conflicting content and collapses
identical/concurrent enqueues. HTTP acceptance is recorded only for a 200 response
with exactly one accepted and zero rejected events. Failure or acknowledgement
rollback leaves delivery pending across restart. Requests can repeat after a
server commit: stable external IDs support downstream deduplication but do not
prove exactly-once Kafka publication or alert persistence.

The only allowed destination is literal `http://127.0.0.1:<port>/v1/ingest/batch`.
Redirects and environment proxies are disabled. Tokens are supplied explicitly;
no hosted credentials or settings are loaded. There is no CLI daemon, automatic
receiver hook, scheduler registration, or activation by environment variable.

Run the synthetic ledger/loopback transport tests with:

```powershell
python -m pytest -q tools/windows/test_synthetic_detection_bridge.py -o addopts=''
```

The HTTP test is a controlled loopback ingest response, not the real Go handler.
The separate Go normalization test exercises the real normalizer, proving stable
retry identity and distinct IDs for every identity dimension and tenant.

## Remaining gates before any staging-only deployment

Docker is unavailable in this environment. No Kafka/fusion/disposable alert
database chain was started, and neither detection matching, promotion, nor
duplicate-alert prevention is verified. Metadata-only limitations in the receipt
audit still apply. Real authenticated ingest authorization must be tested with
the bridge, not inferred from the loopback response harness.

1. In disposable local infrastructure, route labelled positive and negative
   fixtures through real authenticated ingest, Kafka, fusion and PostgreSQL.
   Check cross-tenant refusal, retry after publication and lost acknowledgement,
   duplicate alert prevention, corpus matching and promotion separately.
2. Design a separately reviewed staging bridge with authenticated service
   identity, restricted credentials and a server-provisioned device binding.
   Keep all existing receipts excluded by explicit eligibility/cutover rules.
   The local prototype deliberately rejects hosted URLs; do not simply remove
   this guard and deploy it.
3. Obtain separate staging-only deployment/configuration approval. Provision the
   restricted receiver login documented by the receipt audit. Keep actions and
   continuous collection disabled. Set only the three status API variables above
   in the approved staging API process, never the frontend.
4. Without POST/upload/replay, check receiver GET status, authenticated API GET,
   and the authorized tenant's Connectors page. Compare the current aggregate;
   do not assume the historic count remains unchanged. Verify another tenant
   sees `configured:false`, permission denial prevents upstream access, and
   unavailable upstream status displays unknown volume. Roll back settings if
   verification fails.

## Session verification

- Complete Windows suite with disposable PostgreSQL: **124 passed** before the
  additional concurrent enqueue case; final targeted bridge suite: **7 passed**.
- Authenticated status API with real disposable database lookup and synthetic
  upstream: **6 passed**, 9 dependency deprecation warnings.
- Dashboard component: **7 passed**; frontend `tsc --noEmit`: **passed**.
- New Go identity normalization test: **passed**.
- Broader Go handler/normalizer tests: **failed after the 60-second timeout**
  while existing test setup tried to download the absent ATT&CK bundle from its
  CDN. This is not a passing ingest authorization run. The new identity test
  does not use that network setup and passes independently.
- Negative control in a temporary module copy: removing source epoch caused the
  identity test to fail (`assert 0 == 1`); the real module was never modified.
- Ruff 0.16.10: new Python modules pass lint and formatting. Repository-wide lint
  has **40 existing findings**; format checking flags **54 other files**.
- Mypy 2.4.0 baseline gate ran under Python 3.13 and fails on Windows path
  separator/unmanaged-scope accounting and reports interpreter mismatch with
  the Python 3.11 baseline; no baseline or scanner ceilings changed.

An initial sandbox run had 111 passes, 11 database skips, and 2 DPAPI failures
because impersonation lacked a loaded profile. The complete 124-pass run used
the real user profile and the new loopback-only disposable PostgreSQL cluster.
