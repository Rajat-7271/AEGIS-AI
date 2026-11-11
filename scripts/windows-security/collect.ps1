# AEGIS AI Windows Security metadata collector (Windows PowerShell 5.1+).
# No event payloads or credentials are written to disk.
# Dry-run by default. Sending requires -EnableSend and explicit configuration.
param(
    [string]$ApiBaseUrl = $env:AEGIS_API_BASE_URL,
    [string]$TenantId = $env:AEGIS_TENANT_ID,
    [string]$ConnectorId = $env:AEGIS_CONNECTOR_ID,
    [string]$Token = $env:AEGIS_CONNECTOR_TOKEN,
    [string]$HmacSecret = $env:AEGIS_CONNECTOR_HMAC_SECRET,
    [string]$CheckpointPath = "$env:LOCALAPPDATA\AEGIS-AI\windows-security-checkpoint.txt",
    [int]$IntervalSeconds = 5,
    [switch]$EnableSend,
    [switch]$Once
)
$ErrorActionPreference = 'Stop'
if ($IntervalSeconds -lt 1) { throw 'IntervalSeconds must be positive' }
if ($EnableSend) {
    if (-not $ApiBaseUrl -or -not $TenantId -or -not $ConnectorId -or -not $Token) {
        throw 'Set AEGIS_API_BASE_URL, AEGIS_TENANT_ID, AEGIS_CONNECTOR_ID and AEGIS_CONNECTOR_TOKEN'
    }
    $null = [guid]::Parse($TenantId)
    $null = [guid]::Parse($ConnectorId)
    if (-not $ApiBaseUrl.StartsWith('https://')) { throw 'HTTPS is required for event transmission' }
}
$checkpoint = [long]0
if (Test-Path -LiteralPath $CheckpointPath) {
    $checkpoint = [long]([IO.File]::ReadAllText($CheckpointPath).Trim())
}
function Save-Checkpoint([long]$value) {
    $directory = Split-Path -Parent $CheckpointPath
    if (-not (Test-Path -LiteralPath $directory)) {
        $null = New-Item -ItemType Directory -Path $directory -Force
    }
    $tmp = "$CheckpointPath.$PID.tmp"
    try {
        [IO.File]::WriteAllText($tmp, [string]$value)
        Move-Item -LiteralPath $tmp -Destination $CheckpointPath -Force
    } finally {
        if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force }
    }
}
function Make-Event($entry) {
    $when = $entry.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
    $system = @{
        EventID = [int]$entry.Id
        Channel = 'Security'
        Computer = [string]$entry.MachineName
        EventRecordID = [long]$entry.RecordId
        TimeCreated = $when
        Provider = [string]$entry.ProviderName
    }
    $severity = if ($entry.Id -in @(4625, 1102)) { 'high' } else { 'info' }
    return @{
        external_id = "windows-security:$($entry.MachineName):$($entry.RecordId)"
        severity = $severity
        hostname = [string]$entry.MachineName
        created_at = $when
        raw_event = @{ System = $system; EventData = @{} }
    }
}
function Send-Batch($events) {
    $body = @{
        connector_id = $ConnectorId
        connector_type = 'windows_event'
        source_format = 'raw_json'
        events = @($events)
    } | ConvertTo-Json -Depth 10 -Compress
    $headers = @{ Authorization = "Bearer $Token"; 'X-Tenant-ID' = $TenantId }
    if ($HmacSecret) {
        $hmac = New-Object Security.Cryptography.HMACSHA256
        try {
            $hmac.Key = [Text.Encoding]::UTF8.GetBytes($HmacSecret)
            $hash = $hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($body))
            $headers['X-Signature'] = 'sha256=' + [BitConverter]::ToString($hash).Replace('-', '').ToLowerInvariant()
        } finally { $hmac.Dispose() }
    }
    $uri = $ApiBaseUrl.TrimEnd('/') + '/api/v1/windows-security/batch'
    $response = Invoke-RestMethod -Uri $uri -Method Post -ContentType 'application/json' -Headers $headers -Body ([Text.Encoding]::UTF8.GetBytes($body)) -TimeoutSec 20
    if ([int]$response.accepted -ne @($events).Count -or [int]$response.rejected -ne 0) {
        throw 'Server did not acknowledge the entire batch; checkpoint not advanced'
    }
}
Write-Host $(if ($EnableSend) { 'AEGIS collector: sending metadata only' } else { 'AEGIS collector: DRY RUN (no network requests)' })
do {
    try {
        # RecordId filtering avoids repeatedly fetching an entire Security log.
        $xpath = "*[System[(EventID=4624 or EventID=4625 or EventID=4672 or EventID=4688 or EventID=4720 or EventID=1102) and EventRecordID > $checkpoint]]"
        $entries = @(Get-WinEvent -LogName Security -FilterXPath $xpath -Oldest -MaxEvents 500 -ErrorAction Stop |
            Sort-Object RecordId)
        if ($entries.Count -gt 0) {
            # Process the oldest pending records first; checkpoint only after an acknowledged batch.
            $events = @($entries | ForEach-Object { Make-Event $_ })
            if ($EnableSend) {
                Send-Batch $events
                Save-Checkpoint ([long]$entries[-1].RecordId)
                $checkpoint = [long]$entries[-1].RecordId
                Write-Host "Acknowledged $($events.Count) event(s), checkpoint $checkpoint"
            } else {
                Write-Host "Dry run: $($events.Count) metadata event(s), newest record $($entries[-1].RecordId); checkpoint unchanged"
            }
        }
    } catch {
        # No matching records is normal; permission, query and transport failures are not.
        if ($_.FullyQualifiedErrorId -match 'NoMatchingEventsFound') {
            if ($Once) { Write-Host 'No matching Security events' }
        } else {
            Write-Warning "Collector cycle failed (checkpoint unchanged): $($_.Exception.Message)"
            if ($Once) { throw }
        }
    }
    if (-not $Once) { Start-Sleep -Seconds $IntervalSeconds }
} while (-not $Once)
