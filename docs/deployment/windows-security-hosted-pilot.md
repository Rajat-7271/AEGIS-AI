# Windows Security pilot — hosted deployment runbook

This is the **minimal PostgreSQL-backed path** for the Render/Supabase/Vercel
deployment. It does not require Kafka, ClickHouse, Fusion or the Go ingest
service. The current pilot sends **Security event metadata only** (allowlisted
Event IDs 4624, 4625, 4672, 4688, 4720 and 1102). No usernames, event
messages, command lines or full event bodies are exported.

## Release gates (operator approval required)

1. Confirm draft PR #38 has green checks, review its diff and explicitly
   approve merging into `release/public-mvp`. **Do not deploy merely because
   checks are green.** Verify the production frontend and API are healthy first.
2. Before API rollout, ensure the database migration runner will apply
   `services/api/migrations/121_windows_security_events.sql` using
   `DATABASE_MIGRATION_URL`. Render Free can use the existing
   `AISOC_RUN_MIGRATIONS_ON_BOOT=1` **one-shot** gate; remove the variable
   after the successful migration boot. Never publish the migration DSN.
   Verify the table exists and tenant isolation is enabled before sending.
3. Deploy the approved backend and then the approved frontend. Confirm
   `GET /health` and authenticated `GET /api/v1/windows-security/events`
   (initially empty) respond successfully. A 404 means the new API has not
   been deployed; a 401/403 means authentication or authorization needs review.
4. Only after approval, mint a revocable **connector-push** token with
   `POST /api/v1/inbox/tokens` using an authenticated operator with
   `connectors:write` permission. Example request body:
   `{"template_id":"connector-push","label":"Windows Security pilot"}`.
   Store the returned plaintext token privately; it is displayed only once.
   Optionally configure a unique HMAC secret (16–512 characters) and supply
   that same secret to the Windows shipper. Do not paste tokens or secrets
   into tickets, commits or chat.
5. Obtain the actual tenant UUID from the authenticated tenant configuration.
   Generate a separate connector UUID with PowerShell
   `[guid]::NewGuid().ToString()`. Do not use the example UUIDs from tests.
6. On the authorized Windows PC, install Python and `httpx`
   (`python -m pip install httpx`). Set the following **user-level**
   environment variables privately, with values from your own deployment:

   - `AEGIS_WINDOWS_INGEST_URL`: approved HTTPS API origin, without a path
   - `AEGIS_WINDOWS_TENANT_ID`: actual tenant UUID
   - `AEGIS_WINDOWS_CONNECTOR_ID`: generated connector UUID
   - `AEGIS_WINDOWS_INGEST_TOKEN`: minted connector-push token
   - `AEGIS_WINDOWS_INGEST_HMAC_SECRET`: optional matching HMAC secret

   User-level environment variables are not a secure vault. Use a dedicated,
   least-privileged Windows account and protect its profile; rotate any
   exposed credential. The task runs as the current interactive user.
7. First perform **offline** collection and validation:
   `powershell -File tools/windows/run_security_pipeline.ps1`.
   This does not transmit anything. Security log access may require elevated
   permissions or Event Log Readers membership.
8. After explicit approval to send **real Windows metadata**, make a single
   manual HTTPS trial:
   `powershell -File tools/windows/run_security_pipeline.ps1 -Send -DirectApi`.
   Verify the acknowledged count and the authenticated Data Explorer
   **View Windows Security events** button. Failed or partial acknowledgements
   must not advance the shipper cursor. Retry only after inspecting the error.
9. Only after successful manual verification, optionally install a periodic
   task:
   `powershell -File tools/windows/schedule_security_export.ps1 -Install -Send -DirectApi`.
   Preview without `-Install` is non-mutating. To disable collection, run
   `powershell -File tools/windows/schedule_security_export.ps1 -Remove`.

## Troubleshooting

- **No events:** verify Security log permissions, allowlisted IDs, checkpoint
  continuity and the last 24 hours on the first export. An empty source is not
  an API failure.
- **401:** check bearer token, tenant ID, revocation and HMAC signature.
- **403:** the signed-in analyst may lack `lake:query`; token minting needs
  `connectors:write`.
- **404:** verify the deployed API revision includes the Windows router.
- **422:** inspect the exporter/shipper version and metadata shape. Do not
  disable validation to force ingestion.
- **500 or missing table:** check migration 121 and the production DB role.
- **Events acknowledged but absent in UI:** verify the frontend points to
  the same API/tenant and that the user is authorized; reload the Windows
  events view.
- **Security log cleared or JSONL truncated:** the exporter/shipper stops
  intentionally; investigate before resetting either checkpoint.
- **Duplicate retry:** event IDs are stable and database insertion is
  idempotent per tenant. Acknowledged count means processed, not necessarily
  newly inserted.

This runbook is **not authorization** to merge, deploy, mint tokens, install
scheduled tasks or transmit real data.
