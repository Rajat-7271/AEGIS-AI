# Windows Security staging readiness

## Decision and evidence (2026-11-13)

Dashboard activation remains blocked. No hosted changes, deployment, production
requests, collection, or receipt replay were performed. The 12 genuine staging
receipts were neither selected nor modified. Only staging schema names were read.

Read-only connected inventory found:

- Render workspace `tea-dbl0t7t9fdbs73cil6ug` has one service, including previews:
  `aegis-windows-staging-receiver` (`srv-dbrgqm8u01pc73b7bai0`). It runs Gunicorn
  with `tools/windows/staging_epoch_wsgi.py`, branch
  `codex/windows-security-integration`, free plan, auto-deploy off. This is a
  receipt receiver, not the application FastAPI API or an ingest/fusion service.
- Vercel project `aegis-ai` has an encrypted/sensitive `API_URL` setting targeting
  both Preview and Production, with no branch restriction in the returned
  metadata. The connector withholds its value even on individual retrieval.
  Preview therefore does not prove an isolated API. No deployment was visited.
- Supabase project `hwncacdsoyfkdvvffgzh`, named `aegis-ai-staging`, is separate
  from the main project. A read-only information-schema query found only
  `windows_pilot.security_events_v2` outside platform schemas. There is no
  application `tenants` table to query here. No main-project query was made.

**No isolated application staging API was found in the accessible inventory.**
This does not rule out another account/provider. Repository deployment templates
include Render FastAPI and Fly API alternatives; neither template establishes
the actual deployed API hostname. The configured API hostname, its database
binding, and its deployed revision remain unverified.

## Routing and authenticated tenant

`apps/web/src/components/connectors/WindowsSecurityStatus.tsx`, mounted by
`ConnectorsView`, uses `TenantProvider` and a tenant-specific SWR key. It calls
`apiRequest('/windows-security/status')` every 30 seconds when a tenant exists.
`apps/web/src/lib/api.ts` prefixes `/api/v1`, attaches authentication and the
active tenant header, and falls back to same-origin for a cross-origin browser
base. The catch-all in `apps/web/next.config.js` proxies `/api/v1/:path*` through
server `API_URL` (local fallback port 8000). The browser fallback/default tenant
is not evidence of authorization.

The API router mounts `app/api/v1/endpoints/windows_security.py`.
`GET /api/v1/windows-security/status` requires `connectors:read` and compares
`current_user.tenant_id` with the configured staging binding before upstream
access. `app/api/v1/deps.py` resolves API-key identity from the database key row
(`api_key.tenant_id`), JWT users from verified authentication, and service
identities through the separately validated service path. A tenant query/header
cannot replace the authenticated principal. Development bypass must remain off.

An authorized staging application tenant UUID **could not be determined**.
The receipt schema does not supply one, the local process has none configured,
and Vercel's `NEXT_PUBLIC_TENANT_ID` is a client default, not an authorization
record. Do not reuse test UUIDs or the demo tenant. Resolve the binding from the
intended staging API's authenticated principal and active application tenant row
once its isolated database and API identity have been established.

## Configuration proposal — inert, not applied

| API-process setting | Local verification | Proposed staging value |
| --- | --- | --- |
| `AEGIS_WINDOWS_STAGING_TENANT_ID` | Missing | Verified active staging application tenant UUID; unresolved |
| `AEGIS_WINDOWS_STAGING_STATUS_URL` | Missing | Existing receiver HTTPS origin plus exact `/v2/windows-security/status` path |
| `AEGIS_WINDOWS_STAGING_TOKEN` | Missing | Existing authorized device bearer token from secret storage; never copied into this document |

Hosted API values are **unknown**, not proven missing: no isolated API process
was identified. These names are absent from the returned Vercel variable
inventory, but Vercel frontend configuration is not the FastAPI environment.
The local upload endpoint/device variables are present; they are not substitutes
for the status settings and their values were not printed.

After separate approval, an operator must first identify an isolated FastAPI
service, its staging-only database and credentials, and a revision containing
the status router. Do not point an existing Preview at a shared API or change a
shared Preview/Production variable. If no free isolated service is available,
retain this blocked state; do not provision paid infrastructure.

Stage the three settings only in that API process. Require a canonical UUID,
HTTPS port 443, exact status path, no query/fragment/credentials, and an ASCII
token of at least 32 characters without CR/LF. Never place the token in browser
settings, logs, shell history, or source control. Keep actions, collection,
bridge activation and receipt eligibility unchanged. Confirm the receiver uses
its restricted non-owner database login rather than a BYPASSRLS owner.

Approved read-only acceptance sequence: receiver GET status; authenticated API
GET status; authenticated Connectors panel. Compare the then-current aggregate,
not an assumed historic count. Check another authorized tenant returns
`configured:false` without upstream access, insufficient scope denies access,
and upstream unavailability renders unknown volume. No POST/upload is needed.

Before applying anything, securely record each setting's prior existence/value
and the staging route/revision. Rollback restores prior values or removes only
newly introduced settings in that isolated API and restores its prior route and
revision if changed. Recheck authenticated status and panel. Do not rotate the
receiver token as a dashboard rollback, delete receipts, or modify shared or
production settings. This document does not authorize applying the plan.

## Local integration and limits

Docker is absent. Bounded loopback probes found no listener on 5432, 5433, 9092,
8000, 8080 or 8003. The prior disposable PostgreSQL cluster on 55449 was stopped;
it was briefly started, but connection attempts with assumed bootstrap roles
failed. It was stopped again. A fresh PostgreSQL 16 cluster with explicit
`aegis_readiness_test` bootstrap role ran only on `127.0.0.1:55450` for this work.
Its trust authentication is confined to disposable loopback testing and is not
a hosted configuration proposal.

No available Kafka broker or running ingest/fusion chain was established.
Consequently authenticated ingest → Kafka → real detection → persisted alert,
positive/negative corpus evaluation through that chain, promotion, crash retry,
and duplicate-alert prevention remain **unverified**. No alert was inserted
directly to manufacture a passing integration result.

The new Windows HTTP test uses a real loopback server, ingest handler and
normalizer with controlled credential stores and a capturing publisher. It
proves two credentials can each write their own tenant, cross-tenant and invalid
credentials cannot publish, identical retries retain event identity, and tenant
identities differ. It also explicitly observes repeated publication for a retry;
stable identity is not exactly-once delivery. The credential stores and publisher
are test doubles, not proof of database token lookup or Kafka persistence.

Existing real-PostgreSQL receipt tests verify non-owner RLS, atomic conflict
rollback, concurrent replay, epoch record reuse and retry after lost local
acknowledgement. The synthetic SQLite ledger tests verify duplicate enqueue,
conflicting replay, tenant binding, restart/retry and hosted-destination refusal.
These are receipt/ledger duplicate checks, not duplicate-alert checks.

## Test environment fix and verification

The Go auth setup omitted `AttckDataPath`; the normalizer catalogue startup test
also omitted it. Both entered production's best-effort CDN fallback, whose
120-second HTTP timeout exceeds the 60-second suite deadline. An unrestricted
run reproduced the timeout in `TestNewLoadsTheCatalogueAtBoot`; sandbox socket
denial instead failed the download immediately and hid the timing problem.

Both test setups now use a checked-in empty, explicitly synthetic STIX bundle.
No production loader, authentication check, catalogue assertion, timeout, scanner
ceiling or dependency lock was weakened. A regression test verifies the auth
configuration references a readable JSON bundle. It failed before the fix;
temporarily removing the setting after the fix reproduced the same failure,
and the setting was restored.

- Go handler and normalizer packages, uncached with 60-second timeout: passed,
  including Windows real-HTTP authorization/identity coverage.
- Complete Windows suite with disposable PostgreSQL and real DPAPI profile:
  **125 passed**. Earlier attempts had 11 setup errors from incorrect bootstrap
  role assumptions; the fresh explicit-role cluster resolves those errors.
- Authenticated status API, database-backed key resolution and controlled
  upstream: **6 passed**, 9 dependency warnings.
- Dashboard status component: **7 passed**. Frontend `tsc --noEmit`: passed.
- Ruff **0.16.10** repository lint: **40 findings**; format check: **54 files**
  requiring formatting, matching the prior documented counts. No Python source
  was changed in this milestone and no baseline was raised.
- Mypy baseline gate, mypy **2.4.0** on Python **3.13**: failed, including
  Windows path-separator/unmanaged-scope accounting and the recorded Python
  3.11 interpreter mismatch. This is not a passing Python 3.11 baseline run.
- Attribution, competitor-name and whitespace gates: passed. The disposable
  database was stopped after verification; no test services remain enabled by
  this milestone.

Full pipeline and live authenticated dashboard readiness must not be reported as
passing based on these component results.
