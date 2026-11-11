# Windows Security live collector — safe pilot

This collector is **opt-in**. It reads selected Windows Security event IDs (4624, 4625, 4672, 4688, 4720, 1102), sends **metadata only**, and never writes the token or event payload to disk. The default is a **dry run** (no network traffic, no checkpoint updates).

## Validate on a Windows PC

Open PowerShell with permission to read the Security event log. From the repository root:

```powershell
powershell.exe -NoProfile -File .\scripts\windows-security\collect.ps1 -Once
```

Expected: a dry-run count or `No matching Security events`. A permission or query failure must exit with an error. This does **not** upload any events.

## Controlled sending (requires separate approval)

Only after the API is verified reachable in a nonproduction environment and a **revocable tenant-scoped connector-push token** has been created through an approved provisioning workflow, configure the environment variables **in the current shell**:

- `AEGIS_API_BASE_URL`: HTTPS API origin (no trailing `/api/v1`)
- `AEGIS_TENANT_ID`: tenant UUID
- `AEGIS_CONNECTOR_ID`: connector UUID
- `AEGIS_CONNECTOR_TOKEN`: revocable connector-push token
- `AEGIS_CONNECTOR_HMAC_SECRET`: optional HMAC secret; required when the server token record has one

Do **not** paste credentials into chat, commit them, or store them in command history. The collector transmits only when explicitly invoked with `-EnableSend`:

```powershell
powershell.exe -NoProfile -File .\scripts\windows-security\collect.ps1 -Once -EnableSend
```

For a strictly bounded pilot, pass `-MaxEvents 2` with `-Once`; the default batch cap is 500. Use a dedicated checkpoint path for pilot tests. PowerShell's invariant-culture UTC formatting is required so JSON timestamps validate correctly regardless of regional settings.

Run without `-Once` for repeated polling every 5 seconds. A successful API acknowledgement advances the local record-ID checkpoint; failed requests leave it unchanged. The API is idempotent by tenant and event external ID. The dashboard separately polls the API every 5 seconds.

## MVP acceptance test

1. Verify a new Security log record appears on the PC.
2. Run a single dry-run collection and confirm the record is eligible.
3. With approved staging credentials only, send a single batch and verify its acknowledgement.
4. Check the authenticated Windows Security dashboard for the record's hostname, ID, time and record ID.
5. Repeat the same batch and verify no duplicate appears.
6. Temporarily block API access; verify the checkpoint does not advance, then restore access and confirm delivery.

**Known limits:** This is a polling pilot, not a Windows service. Log rollover/reset, concurrent collector instances, offline backlog retention, and full end-to-end Windows validation require further work. It does not yet establish real-time production readiness.
