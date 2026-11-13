# Isolated staging API preparation

This is an unapplied deployment plan. The existing Windows receipt receiver is
not the FastAPI application, an application tenant authority, or a detection
pipeline. Keep its 12 historic staging receipts and credentials untouched.

## Minimum runtime and boundaries

Use one new free web service from `infra/render/staging-api.yaml` and one new,
dedicated PostgreSQL database in a separate free project/account allocation.
Do not attach an existing application or receiver database, environment group,
domain, agents service, or production/shared routing. If an isolated free
database allocation is unavailable, stop provisioning; do not upgrade a plan.
The database provider is intentionally not provisioned by this Blueprint.

The API Dockerfile builds the exact Poetry main lock through a separate export
stage. Its normal command is the dual-stack `app.scripts.serve`; staging
overrides it with `app.scripts.staging_serve`, which runs the same real
`app.main` application under an outer capability filter. Only login, current
identity, alert reads, Windows status, liveness and readiness are exposed. Uploads, connector
configuration, actions, WebSockets, API key management and other routes return
403. Alert detail reads may lazily persist a narrative; this is a restricted
HTTP surface, not a database read-only role.

Postgres is required for users, API keys, tenant-scoped alerts and audit writes.
Redis is omitted: login throttling uses the existing in-process fallback, so
this is a single-instance test environment, not production-grade throttling.
Kafka, Neo4j, ClickHouse and Qdrant are disabled; every in-process scheduled
worker is disabled explicitly. No service credentials, receipt tokens or
third-party API credentials are needed for this restricted surface.

`ENVIRONMENT=production` deliberately enables existing strict secret checks;
`AISOC_STAGING_ONLY=1` selects this staging entrypoint. Missing flags, secrets,
database host pin or verified TLS fail before application imports. The host pin
is a configuration consistency check: a reviewer must establish ownership and
isolation of that database; matching strings alone cannot prove isolation.

`/livez` reports process liveness. `/readyz` additionally checks the real tenant
table with a three-second budget and returns a sanitized 503 on database
failure. It is not a substitute for checking the complete migration ledger or
running authenticated acceptance. `/health` is deliberately unavailable here.

## Provisioning after separate deployment authorization

1. Review the committed revision and choose a unique staging service name in a
   separate workspace. Never sync this file over an existing Blueprint. Keep
   automatic deploys and previews off. Creating a Blueprint can trigger its
   initial deployment even with automatic deploys off; this batch does not
   authorize creation or sync.
2. Establish a new empty staging database. Record its project identity, host,
   database name and runtime role in private operational records. Use verified
   TLS and a session/direct endpoint compatible with asyncpg; do not use a
   transaction pooler. No paid resources or persistent disks are required.
3. In a private one-off process built from the API lock, apply the repository's
   base schema and migrations using `app.scripts.run_migrations`, following
   `infra/postgres/initdb/` ordering for a fresh database. Set
   `AISOC_MIGRATIONS_REQUIRED=1` and `AISOC_MIGRATIONS_STRICT=1`. Inspect the
   migration ledger: the runner can otherwise log migration failures and exit
   successfully. Do not rely on `create_all` or a successful boot as proof of
   complete migrations. Extensions or role privileges unsupported by a free
   provider are blockers, not reasons to skip a migration.
4. The runner provisions `aisoc_app` from `AISOC_APP_DB_PASSWORD`. Confirm the
   runtime login is non-owner, non-superuser and lacks BYPASSRLS. Remove owner
   credentials and `DATABASE_MIGRATION_URL` from the web runtime; boot migrations
   are forbidden. Keep migration credentials only in the private one-off
   process. Review row-level policies as well as application tenant filters.
5. Provision fresh `Tenant` and `User` rows in a transaction using the real ORM:
   assign `uuid.uuid4()` tenant IDs, unique staging slugs, active tenants and
   verified active users; hash passwords with `get_password_hash`. Use two
   separate tenants for acceptance. Do not use `seed_demo`, a demo UUID, a
   browser tenant hint or the receiver device binding as authorization proof.
   `bootstrap_admin` adopts a default/existing tenant, so do not use it to
   establish a new isolated tenant identity. Keep any bootstrap administrator
   credential private and temporary; normal staging users should have the
   `viewer` role or a narrower reviewed role.
6. For automated reads, use the existing `generate_api_key` and `ApiKey` model
   in that same private provisioning process. Store only the returned hash,
   bind `tenant_id` and `user_id` to the provisioned rows, grant only
   `alerts:read`, and set a short `expires_at`. Transfer the raw key directly
   to secret storage once. Never print it in logs or pass it in command-line
   arguments. Revocation sets `is_active=false`; test it returns 401. Never
   grant `*`, service-token authority or ingest scope for these API checks.
   A separate status-only key needs `connectors:read`. Leave the three receiver
   status variables unset until an independently authorized read-only status
   integration; do not copy them from the Windows collector. Without those
   settings, the existing status endpoint honestly reports unconfigured.
7. Supply independent random signing/metrics/realtime secrets of at least 32
   characters, and a valid Fernet `AISOC_CREDENTIAL_KEY`, through the platform
   secret store. The Blueprint uses `sync:false`, never inline values. Set
   `DATABASE_URL` to the restricted login with `sslmode=verify-full`, pin its
   host in `AISOC_STAGING_DB_HOST`, and use an exact staging console CORS origin.
   Do not copy any production settings or receiver credentials.

## Frontend strategy

Use a separate staging frontend project with a clean environment, its own
artifact and cookies, no production custom domain, and manual deployment only.
At build and runtime set `AISOC_STAGING_ONLY=1`, `AISOC_STAGING_API_URL` to the
reviewed HTTPS staging origin, and `AISOC_STAGING_API_HOST` to that exact host
(the first DNS label must contain `staging`). `staging-routing.cjs` executes
before Next.js resolves backend origins. Missing/mismatched origins, inherited
`API_URL`, sibling backend URLs and public backend URL overrides fail the build.
Unavailable siblings point to closed loopback port 1. Production deployment
mode is refused. Do not promote this artifact or reuse a previous production
build; rewrites are baked at build time. Unsupported panels should show errors;
this limited API does not make the entire console functional.

## Native synthetic testing and remaining gates

The local synthetic bridge accepts explicit synthetic fixtures and literal
loopback ingest only. Its disposable SQLite ledger proves retry identity,
atomic conflicts and HTTP acceptance, not detection or alert persistence.
The existing `scripts/integration/spine_test.py` drives real HTTP services and
can run against native processes, but its default topology also expects
realtime and fixed ports. It assumes a fixed tenant, so it is not the authority
for new staging credentials. The fusion consumer's tests include controlled
publishers/Redis; those doubles do not prove a real Kafka commit or database row.

Docker is not intrinsically required: native PostgreSQL, Redis, a Kafka-compatible
broker, Go ingest, and the locked fusion process can run on loopback. A broker
and fusion dependency environment must actually be available. The synchronous
fusion `/process` route calls `engine.process` directly and does not invoke
the consumer's persistence sink, so it cannot stand in for this pipeline.

Before claiming synthetic end-to-end success, use fresh disposable tenants and
credential-store records, send labelled positive and negative fixtures through
real authenticated ingest, observe Kafka publication and consumer processing,
and query the actual alert store. Verify a positive rule ID, absence for the
negative control, separate tenant identity, retry after lost acknowledgement,
one durable alert after duplicate replay, and consumer restart recovery. Do
not insert an alert directly or replay any genuine receipt to satisfy this gate.

`tests/test_isolated_staging_live.py` automates the read-only acceptance portion
against literal loopback only. Opt in with `AISOC_LOCAL_STAGING_ACCEPTANCE=1`,
`AISOC_LOCAL_STAGING_API`, two distinct tenant API keys in
`AISOC_LOCAL_TENANT_A_TOKEN`/`AISOC_LOCAL_TENANT_B_TOKEN`, and the positive
pipeline's `AISOC_LOCAL_SYNTHETIC_ALERT_ID`. The suite checks both credentials,
own-tenant positive access, cross-tenant denial even with a forged query hint,
anonymous/invalid credential refusal, probes and upload denial. Absent fixtures
are reported as skipped, never as successful isolation. It does not enable
upload or run against hosted services.

For the persistence check also supply `AISOC_LOCAL_SYNTHETIC_DATABASE_URL`
(literal loopback PostgreSQL, database name beginning `synthetic_`),
`AISOC_LOCAL_SYNTHETIC_POSITIVE_EXTERNAL_ID`,
`AISOC_LOCAL_SYNTHETIC_NEGATIVE_EXTERNAL_ID`, and
`AISOC_LOCAL_SYNTHETIC_RULE_ID`. After the producer's positive/retry/negative
sequence has settled, the test opens a read-only transaction and requires the
expected rule and positive external ID on the actual alert row, exactly one
positive row and no negative row for that tenant. It does not itself publish
fixtures or prove consumer recovery; retain the producer and consumer evidence.

## Rollback

Keep the previous staging revision, configuration presence (not merely values)
and a database snapshot in private records before a future manual deployment.
Restore the prior staging artifact and exact prior settings, removing newly
introduced variables rather than assigning empty strings. Do not point staging
at production while recovering. If schema compatibility is uncertain, stop the
service and restore a new isolated database from the pre-change snapshot;
there is no blanket reversible SQL down-migration guarantee. Revoke newly
   issued staging keys, verify old/new credential behavior as appropriate, and
rerun readiness and tenant acceptance. Do not delete receipts or rotate device
tokens as an API rollback. Local rollback checks verify ordinary frontend
routing is unchanged outside staging; a hosted rollback remains untested.

Current platform references checked during preparation:
[Blueprint specification](https://render.com/docs/blueprint-spec.md),
[free service limits](https://render.com/docs/free), and
[compute plans](https://render.com/docs/compute-plans.md). Free services sleep,
have ephemeral filesystems and shared monthly usage limits; capacity and the
API's fit within 512 MB are unmeasured until an authorized deployment. A free
database may expire or pause; no availability guarantee is implied.

## Local verification record

- Targeted staging policy, real application outage/anonymous-auth behavior and
  synthetic bridge: **49 passed, 3 skipped**, one dependency deprecation
  warning. The three live acceptance tests skip because no disposable running
  API, two tenant credentials and consumer-produced synthetic alert fixture
  were configured. These are not live isolation or persistence passes.
- Existing API tenant/auth/health regressions: **35 passed**, nine dependency
  warnings. Tenant query tests use controlled sessions, not a real database.
- Frontend routing including real Next.js rewrite configuration and ordinary
  routing rollback: **4 passed**.
- Go ingest handler and normalizer packages: **both passed**, uncached with a
  60-second timeout. Their loopback publisher checks do not use a real broker.
- Negative control: temporarily removing the outer staging route denial made
  the transport regression fail; the source was restored and tests passed.
- Current public Render JSON Schema validation passed. The platform CLI was
  unavailable; no authenticated platform validation, Docker build, migration
  application, hosted health check or rollback was performed.
- Ruff 0.16.10 passes on all three changed Python files; focused mypy passes on
  those files. Repository Ruff retains **40 findings**, and repository format
  checking flags **54 files**. The full mypy baseline gate fails with Windows
  path/accounting drift (951 reported findings); no baseline or ceiling changed.
- The existing published-secret configuration gate passes. No receiver store,
  hosted API or production endpoint was queried. Native Kafka and Redis
  executables/broker infrastructure were not available, and no fusion-specific
  locked environment was established; consumer persistence remains unverified.

The policy-only CI workflow installs the API's own locked dependency set and
runs these local checks without deployment credentials. Its remote run is
separate evidence and must not be inferred from the local results above.
