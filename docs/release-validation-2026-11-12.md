# Copilot release validation — 2026-11-12

Release verdict: **NOT READY**. No merge, deployment, promotion, production
configuration change, database mutation, or protected-branch push was performed.

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
