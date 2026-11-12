# Copilot release validation — 2026-11-12

Release verdict: **NOT READY**. No merge, deployment, promotion, production
configuration change, database mutation, or protected-branch push was performed.

## PR 53 follow-up: schema, embeddings and Windows validation

### Event spine and Mobile investigation at 861b09e

Integration run 43267998770, job 131357180038 checked out the PR merge
revision `505a3bb061794446e2303dd978a6d51a15fbb51f`, combining head
`861b09e3b32b18d9c9ec55a1f53ebd0c8ca3e6e7` with base
`338f0d304f55b96282d67b917229e93bf1fedcd3`. It pulled
`ghcr.io/beenuar/aisoc-core-api:main` at 17:22:11 UTC and built only fusion
and ingest. The API was healthy, and sign-in succeeded, but the spine's alert
query failed on `alerts.src_ip_class`; the SELECT also references
`src_ip_class_dataset_version`. Neither column exists in this checkout's
model or migration chain. The old log records no API image digest or OCI source
revision. Its exact immutable image and source revision cannot be recovered
from that evidence; resolving today's mutable tag would not establish them.

Database initialization is local to the checked-out tree: Compose mounts
`infra/postgres/initdb` into `/docker-entrypoint-initdb.d`, and
`services/api/migrations` into `/aisoc/migrations`. On an empty volume,
`10_apply_migrations.sh` applies every SQL file in filename order with
`ON_ERROR_STOP`, then `20_runtime_app_role.sh` sets the runtime role password.
The chain ends at `120_tenant_admin_invitations.sql`. API development startup
can additionally invoke `run_migrations`: it sorts SQL filenames, consults
`aisoc_schema_migrations`, applies pending files and records successes. The
init hook itself does not populate that ledger, so a first runner invocation
may reapply the chain. The API Dockerfile starts `app.scripts.serve`, not a
separate unconditional migration command. Startup behavior of the historical
published image is unverified. `create_all` cannot add columns to an existing
table. Adding invented columns here would conceal the mixed-source failure.

The workflow fix builds API, fusion and ingest after the pull, so API code and
mounted SQL come from the same checkout. API and init-hook changes now trigger
the spine job. Image ID, repository digests, labels, checkout SHA and SQL hashes
are recorded before boot. No migration, production setting or schema changed.
YAML parsing and the source/build ordering contract pass; the committed old
workflow fails the same contract as a negative control. Docker is unavailable
locally, so a passing real-container rerun is still required; static validation
does not establish that the complete spine or chaos steps pass.

Mobile run 43267998947's iOS job 131356653781 was cancelled after about
15 minutes with no steps, runner ID zero and an empty runner name. This is
runner allocation/infrastructure evidence, not a compiler diagnostic. The
workflow cancels superseded PR runs, but this evidence does not establish
concurrency as the cause: the sibling Android and unit jobs succeeded and the
run concluded failure. A targeted iOS rerun was accepted; replacement job
131369781473 is queued without a runner at this review. No mobile code change
or timeout increase is justified by the available evidence.

At 861b09e, 39 workflows succeeded, Integration and Mobile failed, and one
Attribution run was cancelled. Backup/restore's successful job skipped its
actual backup operations because those paths were unchanged; this is not a
fresh restore test. Replay evaluation executed successfully. Migration and
upgrade jobs skipped. These details supersede broader pass claims below.

### Classification of the 35 additional mypy findings

The earlier description of all 35 as genuine stack regressions was too broad.
The recorded Windows run uses mypy 2.4.0, Python 3.11 and the unchanged
no-site-packages flags. Counts below are additional findings, not all existing
baseline debt. No baseline, ignore, scope or checker configuration was changed.

| File or group | Count | Classification |
| --- | ---: | --- |
| check_console_route_contract.py, check_route_duplicates.py | 6 | Windows platform API differences: os.killpg, os.getpgid, signal.SIGKILL are POSIX-only. Linux comparison required; these are not route-object errors. |
| golden_pipeline/run_golden_pipeline.py | 7 | Optional values: six union-attr and one operator; validation flow needs explicit narrowing. |
| agents/api/conversation_store.py | 1 | Duplicate parsed annotation across memory and database branches; annotation structure. |
| agents/api/investigate.py | 3 | persisted_run implies run exists, but the boolean does not narrow the optional dictionary for mypy. |
| agents/investigator/report_writer_agent.py | 1 | Repeated dictionary get does not retain string narrowing in the source-name comprehension. |
| agents/main.py | 1 | Real interface mismatch: HuntScheduler has no public running attribute; startup logging reads it. |
| agents/tests/test_drain.py | 2 | Optional lease and assignment of FakeLanes to EntityLanes; test contracts. |
| agents/tests/test_explain_endpoint.py | 2 | Nonreturning async stub and AsyncIterator annotation lacking aclose; test/stream typing contracts. |
| agents/tests/test_orchestrator_router_stream.py | 2 | anext returns Awaitable, while create_task requires a coroutine; inferred task annotation also fails. |
| api/endpoints/playbook_steps.py, api/services/alert_synthesis.py | 2 | Repeated get calls do not narrow optional list/dictionary values. |
| api/tests/api/v1/endpoints/test_alerts_submit.py | 3 | Helpers imported through endpoint module are not declared exports; test import contract. |
| connectors/tests/test_auditd_connector.py, test_kubernetes_audit.py | 2 | Windows platform difference: os.geteuid is unavailable, at lines 660 and 485 respectively. |
| fusion/tests/brute_force_scenario.py, test_brute_force_scenario.py | 3 | Fixture argument typing and replacing a bound worker method; test contracts. |

Totals: eight platform-dependent findings, seven golden-pipeline optional-value
findings, eight application findings and twelve other test/fixture findings.
Application findings include six narrowing/annotation issues, one duplicate
annotation and one scheduler interface mismatch. Classification is not runtime
verification or authorization to suppress errors. A fresh complete run reproduced
992 total findings and the same 35 additional findings across 22 entries. The
baseline remains a blocker. Pinned Ruff lint and formatting pass (2,605 files);
the concurrency gate passes over 89 workflows. The required-check-substance gate
could not run without GH_TOKEN/GITHUB_TOKEN; no pass is claimed for it.

This section supersedes the earlier Pillow and Windows blocker descriptions
below, which record the initial `e4a1f17` validation.

`UpdateConnectorRequest.auth_config` deliberately accepts raw input so the
endpoint can reject malformed credentials without Pydantic echoing secrets.
The published contract is still object-or-null: null means no credential
update; object keys must be catalog secret fields, and blank or null values
preserve stored secrets. `json_schema_extra` left an empty `Any` branch in
`anyOf`. `WithJsonSchema` now replaces the complete field schema while keeping
the redaction behavior. The locked API exporter produces exactly the base
schema: the unchanged breaking-change detector reports zero total changes
against `338f0d304f55b96282d67b917229e93bf1fedcd3`.

The compatible secure dependency path is Qdrant client 1.20.0, FastEmbed 0.9.1,
and Pillow 13.0.0 in both agents and threatintel. Qdrant 1.19.1's extra required
FastEmbed below 0.9; 1.20.0 permits 0.9, and FastEmbed 0.9.1 permits Pillow below
14. Poetry resolved both locks natively, with explicit security floors and no
incompatible overrides. Exactly these three package versions changed in each
lock. Both service environments pass `pip check`.

A test using the real installed SDK and its local vector database exposed the
storage adapter's obsolete `search` call, which permissive mocks had accepted.
The adapter now uses `query_points` and reads `results.points`; the local test
proves retrieval and cross-tenant exclusion. Real CPU inference with the
configured `BAAI/bge-small-en-v1.5` model produced a finite, normalized
384-dimensional vector. Inference in the local database regression itself is
substituted with an explicitly synthetic test vector.

| Follow-up validation | Result |
| --- | --- |
| Connector, endpoint and credential vault tests | 43 passed |
| OpenAPI detector regression suite | 29 passed |
| Locked OpenAPI export check and base comparison | Pass; zero schema changes |
| Agents memory and report suites | 40 passed, 1 skipped |
| Threatintel complete suite, including real local vector database | 128 passed |
| Qdrant isolation suite | 7 passed |
| Ingest Go suite on Windows, `go test ./... -count=1` | Pass |
| Mypy path self-test, using real mypy subprocesses | 25 cases passed |
| Pinned Trivy 0.74.0, tracked snapshot, unchanged CI policy | Zero reportable vulnerabilities; previously 21 Pillow findings |
| Ruff lint and whole-tree format check | Pass |
| Negative controls | Schema, broker advice, vector search and mypy paths all failed for their expected reasons with fixes reverted; all restored |

The broker fix recognizes Windows' `actively refused` reader-log text in the
shared classifier. The real unreachable-broker test now offers operator advice
on Windows. Mypy diagnostics are normalized to forward slashes before baseline
comparison and unmanaged-scope membership checks. Credential test fixtures now
use the real ORM class, and secret-field names retain their non-null type.

### Remaining blockers and latest original-head CI

All 40 workflow runs for `e4a1f17` were reviewed: 36 succeeded and four failed.
The failed workflows were OpenAPI compatibility, Security (only Trivy),
Integration (event spine), and Mobile (the iOS job was cancelled). Android APK
and mobile typecheck/unit-test jobs succeeded. The cancelled iOS log could not
be retrieved: the log endpoint returned BlobNotFound. No iOS pass is claimed.

The spine job builds fusion and ingest from this branch but deliberately runs
the published `main` API image. That image selects `alerts.src_ip_class` and
`alerts.src_ip_class_dataset_version`; neither is in this branch's Alert model
or migrations, and its database rejects the SELECT. This is a mixed-version
image/schema failure, not evidence that this branch's ORM requires new columns.
The workflow and migrations were not weakened or changed to accommodate it.
The backup/restore and replay-evaluation integration jobs passed.

The main `CI` workflow did not run for PR 53: its pull-request filter only
targets `main` and `develop`, while this draft targets PR 52's branch. Its
absence is not a passing lint/typecheck/build verdict.

With the exact recorded mypy 2.4.0 on Python 3.11, after the path fix, the
baseline still fails with 35 additional findings across 22 file/error-code
entries (992 findings total). These include route-gate attribute access,
golden-pipeline optional values, conversation-store redefinition, investigation
optional results, scheduler state, report-writer types, and existing tests in
agents/API/connectors/fusion. The same issues remain with mypy 2.4.1; changing
checker versions does not repair them. No baseline increases, ignores or
scope exclusions were added.

Real Postgres-backed connector validation and a complete authenticated browser
flow remain unverified; no local database/container stack was available. An
attempt to collect the entire repository test tree in the threatintel-only
environment failed at collection on an unavailable backup-crypt dependency;
only the explicitly listed suites are reported as passing. Fresh pushed-head
CI, successful iOS validation and the unresolved type/integration issues remain
release requirements. The PR stays draft; no merge or deployment is authorized.

## Verified stack

All three PRs were open drafts and mergeable when inspected. The checkout was
clean on `fix/blitz-copilot-tool-output-guard` at
`6e59632fe4b7aa2ab0fcc74cde40850d579ea6fa`. Remote refs were fetched explicitly;
the original fetch configuration only covered that branch.

| PR | Base branch / SHA | Head branch / SHA |
| --- | --- | --- |
| 47 | fix/sample-data-onboarding / 25104a5994a13ccbd6d3d0dd2388b8d81af8ae4b | fix/blitz-copilot-tool-output-guard / da0b53abce643ca1b113dcc577ef8340b5035522 |
| 51 | fix/blitz-copilot-tool-output-guard / da0b53abce643ca1b113dcc577ef8340b5035522 | fix/copilot-general-knowledge-grounding / ec6cdee52024b26b5e800979ace83a111acfc2e4 |
| 52 | fix/copilot-general-knowledge-grounding / ec6cdee52024b26b5e800979ace83a111acfc2e4 | fix/copilot-markdown-formatting / 338f0d304f55b96282d67b917229e93bf1fedcd3 |

Both dependency heads are ancestors of PR 52. Fixes are isolated on
`fix/copilot-release-ci`, based on PR 52. The eventual stack target is
`fix/sample-data-onboarding`; PR 47 records that this is an automatic deployment
source, so merging into it requires a separate production release decision.

## CI evidence before fixes

Latest returned workflow runs for PR 47: 29 success, 5 failure; PR 51: 29 success,
5 failure. Both fail hosted hostname, tenant isolation, console MFA, invitations,
and Security. PR 52 already incorporates fixes for the first four.

PR 52: 35 success, 2 failure across 37 returned workflows. Security run
43249354770 passes Checkov, tfsec, Semgrep and claim ratchets, but fails Gitleaks
and Trivy. OpenAPI run 43249355074 fails schema comparison. Actual failing job
logs were retrieved. New fix-PR checks must be assessed separately; these are
not results for the fix branch.

## Changes and causes

- `.github/workflows/check-openapi.yml`: replace duplicated unbounded dependency
  lists with `service_requirements.py api --locked --only main`, installed with
  `--no-deps`. CI had Pydantic 2.14.3 while the API locks 2.14.0. Include workflow
  and requirements-exporter changes in PR path triggers.
- `docs/openapi.yaml`: regenerate with locked dependencies. Adds actual bearer
  invitation validation/redemption routes and simulation request schema; reflects
  credential replacement validation. Connector responses still omit `auth_config`;
  malformed credential inputs are manually validated to avoid echoing secrets.
  Invitation endpoints intentionally parse their request bodies inside handlers,
  so generated OpenAPI does not describe those bodies. This remains a documentation
  limitation, not proof of unauthenticated tenant access.
- `services/ingest/go.mod`, `go.sum`: native Go update of x/net 0.60.0 to 0.62.0,
  selecting required x/sync, x/sys and x/text updates.
- `services/realtime/package-lock.json`: npm update of body-parser 1.20.8 to 1.20.9.
- API lock: brotli 1.2.1, brotlicffi 1.2.1.0, dnspython 2.9.2,
  graphql-core 3.3.2, pyasn1 0.6.5.
- Agents lock: brotli 1.2.1, brotlicffi 1.2.1.0, filelock 4.2.10;
  compatible fastembed 0.8.1 was checked but still caps Pillow below 13.
- Threatintel lock: filelock 4.0.3 to 4.2.10. Filelock's major upgrade is required
  by the reported fixed-version floor. Poetry generated all lock metadata.
- Workspace manifests and pnpm lock: Next.js and matching lint config 16.4.1,
  body-parser >=2.4.0, joi >=17.13.9, follow-redirects >=1.16.2.
- Separate mobile manifest/lock: decode-uri-component >=0.5.1, node-forge
  >=1.4.1, undici 6.x >=6.29.1. Native pnpm regeneration retained unrelated pins.
- `.gitleaksignore`: exact fingerprint `render-free.yaml:generic-api-key:75`.
  The finding is the AISOC_DISABLE_NEO4J flag followed by a boolean, not a
  credential. It exists since b18c8da93023c493e9e80fd7ac1a5bd768d26e1e.
  No credential rotation is indicated by this finding.
- Python source/test changes: safe import ordering, annotation cleanup and
  formatting required by Ruff 0.16.10. ASTs were compared against the original
  after normalizing imports and the equivalent forward annotation; no other
  AST differences were found. No scanner ceilings were changed.

The vulnerable dependency manifests were unchanged between the onboarding base
and PR 52: these findings predate the Copilot stack.

## Executed validation

| Validation | Result |
| --- | --- |
| Locked OpenAPI before regeneration | Fails for the reported missing paths/schema |
| Regenerated OpenAPI check | Pass, including after dependency updates |
| Original schema negative control | Fails again, exit 1 |
| API credential, vault, simulation tests | 23 passed |
| API invitation and connector endpoint tests | 35 passed, 1 database-dependent skip |
| Copilot transport, fallback, grounding, tenant tests | 140 passed with mocked provider |
| Additional agents persistence, report, recon, drain, simulation tests | 39 passed, 1 skipped |
| Realtime tests | 35 passed |
| Realtime build, typecheck, lint | Pass |
| Web narrative/status tests | 20 passed |
| Actual Copilot renderer tests | 4 passed: headings, paragraphs, lists, fenced paths, escaped markup |
| Web typecheck, lint, production build | Pass; lint has 86 warnings, zero errors |
| Mobile tests and typecheck | 42 passed; correctly named script is `typecheck` |
| Threatintel tests and pip consistency | 127 passed; no broken requirements |
| API and agents pip dependency consistency | Pass |
| Poetry lock checks: API, agents, threatintel | Pass, manifest deprecation warnings |
| Service requirements exporter self-tests | Pass |
| Route auth inventory | Pass: 820 routes, zero unclassified open routes |
| Hosted hostname and vendored CORS check | Pass |
| Ruff lint and full-tree formatting | Pass: 2,603 Python files formatted |
| Git diff whitespace check | Pass |
| Attribution check over 46 committed changed files | Pass |
| Go suite | Fails TestAnUnreachableBrokerSaysSo on Windows |
| Go module checksums | All modules verified |
| mypy baseline | Fails on Windows path separator identity and other baseline differences; not updated |

The Go failure occurs because Windows says the target actively refused the
connection; the existing advice classifier recognizes the literal Linux phrase
`connection refused`. Linux CI must independently validate the suite.

Gitleaks 8.21.2 passes with zero findings on the clean tracked-file snapshot
using the repository's exact fingerprints converted to Windows separators for
the Windows binary. The ordinary Windows scan otherwise fails to match the
existing slash-based allowlist and scans local virtualenvs absent from CI.
Linux CI remains the authoritative check of the committed slash-based file.

Trivy 0.74.0 was rerun with CI's HIGH/CRITICAL, ignore-unfixed, plans exclusion,
and YAML ignore policy on the clean tracked-file snapshot. **52 finding instances
became 21**: all remaining findings are Pillow 12.3.0 in agents, 4 CRITICAL and
17 HIGH, fixed in 13.0.0. No other manifest has remaining reportable findings.
A whole-workspace attempt timed out scanning local virtualenv bytecode; the
tracked snapshot run completed and is the reported result. The gate remains red.

## Copilot verification limits

Mocked HTTP-provider regressions assert one request per user turn, preserve the
user message, reject fabricated tool-call output, and cover both chat transports,
provider failure honesty, general knowledge, grounding and tenant boundaries.

Two real service-route smoke requests used the already configured explicitly
free provider model and isolated test principals, without a database. Chat and
streaming both returned HTTP 200, `source: llm`, and the correct short answer to
2 plus 2. This is real provider verification, not a production browser session.
Credential values were never included in output or changes.

Frontend inspection confirms the request-in-flight ref blocks same-tick duplicate
submits, sends occur in user handlers, and the observed effect only scrolls.
The entire authenticated browser-to-production-data path was not exercised.
No real Postgres instance was available for database integration tests. No live
telemetry claims or shell execution were used in the smoke requests.

## Release requirements and rollback

Resolve the Pillow/fastembed constraint with a supported, tested dependency path;
do not force-install Pillow outside the lock contract or suppress its findings.
Require new Linux CI success, database-backed invitation/tenant tests and an
authenticated browser smoke test before release. Windows mypy and broker-advice
validation remain unresolved local limitations.

Land the fix PR into PR 52's head first, then consolidate 52 into 51, 51 into 47,
and finally 47 into the onboarding target only after all gates and explicit
release authorization. Recheck SHA/mergeability and CI after each base changes.
Do not bypass the automatic-deployment boundary.

Keep the current production deployment and its previous immutable deployment
available. Record those exact deployment IDs before any future release; this
session did not inspect or change them. Fixes introduce no database migration or
production secret changes. Revert fix commits through a development PR if needed;
any later production rollback should restore the previously recorded deployment
artifact, not rebuild an unpinned tree.
