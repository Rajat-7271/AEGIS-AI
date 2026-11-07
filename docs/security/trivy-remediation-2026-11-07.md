# Trivy remediation — isolated migration branch

This record is based on the **actual** Trivy job log for [Security run 42376932174](https://github.com/Rajat-7271/AEGIS-AI/actions/runs/42376932174) at migration commit `944353050cb56d8f973abd3c6c4f14704df87b22`. It is not a claim that the vulnerabilities are fixed.

## Scan inventory

| Dependency source | HIGH | CRITICAL | Total |
|---|---:|---:|---:|
| `services/agents/poetry.lock` | 18 | 6 | 24 |
| `apps/mobile/pnpm-lock.yaml` | 9 | 0 | 9 |
| `services/api/poetry.lock` | 6 | 2 | 8 |
| `pnpm-lock.yaml` | 4 | 2 | 6 |
| `services/ingest/go.mod` | 1 | 0 | 1 |
| `services/realtime/package-lock.json` | 1 | 0 | 1 |
| `services/threatintel/poetry.lock` | 1 | 0 | 1 |
| **Total** | **40** | **10** | **50** |

The scan's other five jobs (Semgrep, Checkov, tfsec, Gitleaks, claim-to-gate matrix) succeeded. Some other integration workflow jobs were skipped; do not call them passes.

## Patch floors explicitly identified by the Trivy log

| Source | Package | Locked version | Fixed version reported |
|---|---|---|---|
| ingest | `golang.org/x/net` | `v0.60.0` | `v0.62.0` |
| realtime | `body-parser` | `1.20.8` | `1.20.9` or `2.4.0` |
| API | `brotli` | `1.2.0` | `1.2.1` |
| API | `brotlicffi` | `1.2.0.2` | `1.2.1.0` |
| API | `dnspython` | `2.8.0` | `2.9.0` |
| API | `graphql-core` | `3.3.0` | `3.3.1` |
| API | `pyasn1` | `0.6.4` | `0.6.5` |
| threatintel | `filelock` | `4.0.3` | `4.2.1` |

The remaining advisory rows and exact fixed versions should be read from the same job log before editing, especially Pillow/Brotli in agents, Next.js in the web workspace, and decode-uri-component/node-forge/undici in mobile.

## Safe implementation order

1. **Isolate:** make dependency changes on `fix/trivy-dependency-remediation`, branched from `migration/upstream-parity`; never touch `release/public-mvp`.
2. **Smallest compatible updates:** regenerate `go.mod` **and** `go.sum` using Go tooling; regenerate `services/realtime/package-lock.json` with npm. Realtime uses Express 4; prefer compatible `body-parser` 1.20.9 over forcing 2.x.
3. **Python:** use Poetry to resolve each affected lockfile; respect the measured FastAPI/OpenTelemetry/sqlglot bounds and the explicit MCP version. Confirm `poetry check` and run service tests.
4. **Web/mobile:** regenerate pnpm locks using the repo's `pnpm@8.15.1`; inspect transitive overrides and verify Next.js/eslint-config-next stay aligned.
5. **Verify:** frozen installs, unit/integration tests, TypeScript builds, Go tests, OpenAPI checks, tenant isolation, investigation evidence regression, and a new Trivy filesystem scan. Never hand-edit integrity hashes or disable the scanner.
6. **Promote only after review:** require zero fixable HIGH/CRITICAL findings and passing applicable gates. PR #3 remains draft; do not merge or deploy to production without explicit user approval.

**Status:** remediation investigation documented; no dependency upgrades or tests are claimed by this file.
