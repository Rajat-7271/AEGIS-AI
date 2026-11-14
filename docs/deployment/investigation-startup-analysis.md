# Investigation startup incident analysis

Status: locally reproduced defects fixed; the reported live request is not attributed to a confirmed live exception. No merge, deployment, production configuration change, or production database write was performed.

## Request path

1. `CaseWorkspace` calls `casesApi.investigate`, which POSTs to `/api/v1/cases/{case_id}/investigate`. The frontend rewrite sends cases routes to the core API; its agents origin is not the API process's agents origin.
2. `services/api/app/api/v1/endpoints/cases.py:case_investigate` requires `cases:write`, resolves the case within the authenticated tenant, and loads linked alert evidence from PostgreSQL. The caller cannot select another tenant.
3. `_agents_proxy` uses `AGENTS_SERVICE_URL`, then `AGENTS_API_URL`, then the compose agents origin. It sends the agents service token and authenticated tenant header. HTTP transport errors become 503; upstream error statuses are propagated.
4. `services/agents/app/api/investigate.py:launch_investigation` authenticates the service token and tenant scope, allocates a run ID, and schedules `_run_and_store`. The alternative router is opt-in; the default is `InvestigatorOrchestrator`.
5. The orchestrator builds context, starts the PostgreSQL investigation ledger row, and runs recon, forensic analysis, responder planning, groundedness and report writing. Chat models use per-role pins and the shared LLM routing/factory. An explicit provider base URL takes precedence over the gateway; an unconfigured gateway alias raises `UnroutableModelError`.
6. Steps, terminal state and reports are persisted through the agents ledger. Realtime publication is best-effort. Polling first uses the process-local run and then the persisted ledger. Background model failure occurs after launch acceptance; it does not by itself explain a startup transport 503.

## Reproduced defects and changes

- The Render manifest supplies `AGENTS_API_URL` using `hostport`, without a scheme. `_agents_proxy` passed that address directly to HTTPX. Actual HTTP dispatch raised `httpx.UnsupportedProtocol: Request URL is missing an 'http://' or 'https://' protocol.`, which that helper translated to 503. Normalize bare internal addresses to HTTP while preserving explicit schemes. This is a demonstrated configuration-triggered defect, not a verified diagnosis of the supplied production case ID.
- Cases and linked alerts advanced to investigating before dispatch succeeded. Move dispatch and upstream rejection handling ahead of those mutations. A refused connection or upstream 401/503 now leaves both statuses unchanged.
- A duplicate evidence query replaced the canonical payload with a smaller projection that dropped original raw events. Reuse the canonical payload, including tenant-scoped alerts and truncation metadata.
- The real graph emitted `done` with a failed final state when its model gateway was absent. The ledger correctly said failed but the background consumer changed the poll result to completed. Preserve the failed state and reason, and emit a failure event instead of success.

## Deployment and PR #47

PR #47 is a draft Copilot output guard based on `fix/sample-data-onboarding`; it changes Copilot behavior, not this cases startup path. The services share infrastructure and LLM routing, so a common deployment outage remains possible, but the output guard does not explain the reproduced URL-scheme failure. The separate reported session-pool incident in draft PR #56 is another possible shared dependency problem, not established as the cause here.

Render workspace discovery succeeded, but no workspace was selected. The Render skill requires explicit workspace identification before service/log access. Workspace confirmation was requested and had not been received when this report was prepared. Therefore live service logs, deployed environment values, routing targets, authentication configuration, agent health and database capacity were not verified. Another source of 503 is the agents tenant-auth dependency when no credential material is configured; this must be distinguished from the proxy transport exception using the actual response detail and correlated logs.

## Validation

- Disposable loopback PostgreSQL 16: all 135 repository migrations applied. The local cluster needed the expected `aisoc` owner role; no production database was used.
- 81 focused API tests passed, including eight real upstream HTTP/PostgreSQL dispatch cases covering scheme-less and HTTP addresses, success, upstream 401/503 and connection refusal. The upstream is a controlled test server; these tests do not claim real LLM completion.
- 45 focused agents tests passed, including real launcher/authentication/orchestrator/ledger execution with the model gateway intentionally absent. The accepted request created a real persisted investigation, failed with the real routing exception, and polling agreed with the ledger. No telemetry or model response was invented.
- Negative controls: restoring the original cases handler caused all eight new API transport regressions to fail; restoring the original agents handler caused the live failure-consistency regression to fail. Restoring the fixes passed again.
- Changed Python files pass Ruff 0.16.10 lint and formatting. Repository-wide lint reports 16 errors outside the changed files; repository-wide formatting also fails outside the changed files. The required mypy baseline check failed with Windows path-separator mismatches and existing baseline findings. Direct before/after checks of the API and agents trees produced identical finding counts; neither changed handler adds type findings. Attribution and competitor-name gates passed.

A successful live provider-backed investigation and production incident attribution remain unverified. They require access to the deployed service logs/configuration and a permitted non-production provider-backed environment with real supplied evidence. A controlled upstream acceptance or an intentionally failed real investigation must not be presented as a successful security investigation.

The draft branch disables its frontend preview deployment. Do not merge or deploy without a separate authorization.
