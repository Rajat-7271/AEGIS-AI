# Windows Security staging integration

This opt-in integration collects genuine local Security **metadata** into a
transactional SQLite outbox and sends bounded v2 batches to the isolated
PostgreSQL receiver. Supabase is supported through its PostgreSQL connection;
the workstation never receives a database password or Supabase service key.
No network transfer occurs without `--send`. Nothing here deploys a service.

The allowlist is 4624, 4625, 4672, 4688, 4720, and 1102. Only event ID, channel,
computer, record ID, UTC time, and provider are retained. Event messages,
usernames, command lines, and EventData are excluded. Computer names are still
telemetry: approve their transmission before enabling upload.

The existing Connectors dashboard shows committed staging receipt counts through
the authenticated API. These records are **not connected to detection, alert
promotion, or agent triage**. A receipt is not a detection result.

## Source continuity and recovery

`collector.py --initialize` explicitly creates a new epoch and starts **after
the newest retained Security record**. It imports no history. Existing v1
JSONL/checkpoint files and the earlier continuity prototypes remain untouched.

Every scan checks the saved record's exact XML SHA256 before and after reading
the next oldest-first page, then verifies the page's final record again. The
hash stays local; raw XML is never written to the outbox or transmitted. All
record IDs are scanned, including unselected event types, so an idle allowlist
does not leave a stale witness unnecessarily.

An XML witness is not a Windows-issued log-instance ID. Missing/overwritten
anchors, changed content, record regression, read failures, corrupt state, and
ambiguous history stop collection. The software never guesses that a cleared
or replaced log is continuous. Restored identical log content cannot be
distinguished from the original; this is not a tamper-proof forensic collector.

SQLite WAL with `synchronous=FULL` commits selected events and the scan cursor
together. Server acknowledgement deletes only the exact pending batch in a
second transaction. Lost responses or failed local acknowledgements replay;
the server key includes device, channel, epoch, computer, and record ID.
Conflicting content rolls back the entire server batch. The receiver refuses a
connection already inside a transaction so a savepoint cannot masquerade as
durable acceptance.

One process owns each spool. At 100,000 pending records collection pauses without
advancing its cursor; uploads continue. Storage errors stop the process. Preserve
the spool, its WAL/SHM files, and status log together. Do not edit SQLite rows or
delete checkpoints to bypass a stop. Once the source witness expires, explicitly
record the coverage gap, drain the old spool with `--send --upload-only`, stop
the old task, and initialize a **new directory/epoch** after operator review.
Never reinterpret v1 history as verified v2 history.

## Staging database and receiver configuration

Use only a separately identified staging database and existing free capacity.
Applying SQL or updating hosted code is deployment work and needs approval.
No hosted migration has been applied as part of this implementation.

After that approval, the staging database administrator applies:

```powershell
psql "$env:AEGIS_WINDOWS_STAGING_ADMIN_DATABASE_URL" -v ON_ERROR_STOP=1 -f .\tools\windows\staging_postgres_epoch_schema.sql
```

The schema creates a NOLOGIN `windows_security_receiver` capability role with
only schema USAGE and table SELECT/INSERT. The administrator grants membership
to the **existing dedicated staging login**, substituting its actual identifier:

```sql
GRANT windows_security_receiver TO dedicated_staging_login;
```

Do not use a browser role, production login, table owner, superuser, or BYPASSRLS
login for the receiver. RLS permits SELECT and INSERT only for that role and the
transaction-local authenticated device context. Without context, SELECT returns
no rows and INSERT fails. There are no UPDATE/DELETE policies. Browser roles
receive no grants; leave `windows_pilot` outside the exposed Data API schemas.
The credential-to-device mapping is currently **one device per receiver**.

Receiver environment:

| Variable | Value |
| --- | --- |
| `AEGIS_WINDOWS_DEVICE_ID` | Provisioned staging device identifier |
| `AEGIS_WINDOWS_STAGING_TOKEN` | Existing per-device token, at least 32 ASCII characters |
| `AEGIS_WINDOWS_STAGING_DATABASE_URL` | Dedicated staging login; verified TLS PostgreSQL URI |

Use `sslmode=verify-full` with the provider CA/root certificate. Use the shared
session pooler when IPv4 is required; automatic prepared statements are disabled
for pooler compatibility. Never put a DSN/token in source, shell arguments, or a
`NEXT_PUBLIC_` variable. The receiver is `staging_epoch_wsgi:application` under
`tools/windows`; retain the existing staging HTTPS gateway, request/connection
limits, and bounded WSGI workers. The stdlib loopback adapters are test harnesses.
The WSGI receiver also caps authenticated requests at 60 per minute per worker;
that process-local limit does not replace gateway quotas or network timeouts.
No paid worker, database, scheduler, or network service is required by this code.

Authenticated routes:

- `GET /v2/health/ready`: connection, receiver-role membership, and table privileges.
- `POST /v2/windows-security/events`: strict bounded metadata batch, atomic commit.
- `GET /v2/windows-security/status`: device-scoped durable count, last receipt,
  highest record ID across epochs, and epoch count. Counts reflect retained rows.

For dashboard visibility, configure the API server (never the browser) with
`AEGIS_WINDOWS_STAGING_TENANT_ID`, `AEGIS_WINDOWS_STAGING_STATUS_URL` (the HTTPS
status route), and `AEGIS_WINDOWS_STAGING_TOKEN`. The API requires
`connectors:read` and binds visibility to the authenticated principal's tenant.
Other tenants receive `configured:false` without any upstream call. Receipt
counts do not measure collector health, source coverage, local queue depth, or
end-to-end latency. The dashboard shows errors as unknown, never zero.

## First controlled real-event test

Prerequisites: explicit upload approval, approved deployed staging receiver/schema,
existing device credential, staging HTTPS readiness, and a Windows account with
Security-log read access. Do not change audit policy or generate security events
for this test. Wait for normal machine activity. Use Python 3.11 or newer; the
workstation collector needs only the standard library.

Run from the repository root in the permitted Windows account. Supply the
approved device and full staging events URL interactively:

```powershell
$env:AEGIS_WINDOWS_DEVICE_ID = Read-Host 'Approved staging device ID'
$env:AEGIS_WINDOWS_STAGING_ENDPOINT = Read-Host 'Approved staging HTTPS v2 events URL'
$testDirectory = Join-Path $env:LOCALAPPDATA ('AEGIS-AI\controlled-' + [guid]::NewGuid().ToString('N'))
$spool = Join-Path $testDirectory 'spool.sqlite'
New-Item -ItemType Directory -Path $testDirectory | Out-Null
$acl = Get-Acl -LiteralPath $testDirectory
$acl.SetAccessRuleProtection($true, $false)
$identity = [Security.Principal.WindowsIdentity]::GetCurrent().Name
$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($identity,'FullControl','ContainerInherit,ObjectInherit','None','Allow'))
Set-Acl -LiteralPath $testDirectory -AclObject $acl
python .\tools\windows\collector.py --spool $spool --initialize
# Wait for ordinary new events, then collect locally and inspect counts only.
python .\tools\windows\collector.py --spool $spool
python .\tools\windows\collector.py --spool $spool --status
```

If pending is zero, collect again later. Do not fabricate events. After approval
to send the pending metadata, load the existing token without echoing it:

```powershell
$secret = Read-Host 'Existing staging device token' -AsSecureString
$ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secret)
try { $env:AEGIS_WINDOWS_STAGING_TOKEN = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr) }
finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr) }
try {
    $statusUri = $env:AEGIS_WINDOWS_STAGING_ENDPOINT -replace '/events$', '/status'
    $headers = @{Authorization = 'Bearer ' + $env:AEGIS_WINDOWS_STAGING_TOKEN}
    $before = Invoke-RestMethod -Uri $statusUri -Headers $headers -MaximumRedirection 0 -TimeoutSec 120
    python .\tools\windows\collector.py --spool $spool --send --upload-only
    if ($LASTEXITCODE -ne 0) { throw 'Upload not acknowledged; preserve spool for replay' }
    $after = Invoke-RestMethod -Uri $statusUri -Headers $headers -MaximumRedirection 0 -TimeoutSec 120
    [pscustomobject]@{Before=$before.events_received; After=$after.events_received; LastReceipt=$after.last_received_at}
    python .\tools\windows\collector.py --spool $spool --status
} finally {
    Remove-Item Env:AEGIS_WINDOWS_STAGING_TOKEN -ErrorAction SilentlyContinue
    Remove-Variable headers, secret -ErrorAction SilentlyContinue
}
```

One invocation sends at most 100 pending records. Confirm the expected new-row
delta in Supabase and the Connectors receipt panel; repeat `--send --upload-only`
for additional batches. On a lost response, retry the preserved spool and verify
that committed identities do not multiply. An empty queue makes no network call.
Keep counts, UTC receipt time, and test outcome as evidence; do not publish payloads.

## Optional background task

`install-security-collector.ps1` registers a current-user interactive logon task,
initializes a fresh protected directory, and optionally stores an existing token
using user-bound Windows DPAPI. It never starts the task during setup. The
limited task identity must already have Security-log read access; an elevated
interactive shell does not prove the limited scheduled task has access.

```powershell
.\tools\windows\install-security-collector.ps1 -PythonPath (Get-Command python.exe).Source -DeviceId $env:AEGIS_WINDOWS_DEVICE_ID
# For approved uploads, use a new installation and explicitly add:
# -EnableUpload -Endpoint $env:AEGIS_WINDOWS_STAGING_ENDPOINT
Start-ScheduledTask -TaskName 'AEGIS-Windows-Security-Staging'
Get-ScheduledTaskInfo -TaskName 'AEGIS-Windows-Security-Staging'
Stop-ScheduledTask -TaskName 'AEGIS-Windows-Security-Staging'
```

Network errors retain the batch and retry with bounded HTTPS attempts and a
slower polling interval. Task Scheduler restarts failed processes up to three
times at one-minute intervals; a later logon triggers it again. Continuity and
disk errors never rotate an epoch automatically. The task runs only while the
user is logged in; it is not a boot-time Windows service. Status logs contain
counts and errors, rotate at 1 MiB, and retain one previous segment. To uninstall,
stop then unregister the named task; preserve its state directory for review.

## Targeted verification

```powershell
python -m pytest -q tools/windows -o addopts=''
# Set only an isolated local PostgreSQL DSN to enable real database tests:
$env:AEGIS_WINDOWS_TEST_DATABASE_URL = Read-Host 'Disposable local PostgreSQL DSN'
python -m pytest -q tools/windows/test_staging_postgres_integration.py -o addopts=''
npx.cmd --yes pnpm@8.15.1 --filter @aisoc/web type-check
npx.cmd --yes pnpm@8.15.1 --filter @aisoc/web test -- src/components/connectors/WindowsSecurityStatus.test.tsx
```

Fixtures are labelled synthetic; tests do not create Windows events. Native probe
fixtures exercise the real PowerShell script, including localized empty results,
reset races, and missing witnesses. PostgreSQL tests cover non-owner RLS roles,
transactional replay and conflict rollback, WSGI HTTP receipts and storage failure.
Passing these tests does not establish genuine Windows-to-Supabase delivery.
