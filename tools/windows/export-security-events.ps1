# AEGIS AI — local Windows Security metadata exporter (pilot).
# Read-only against Event Viewer. Writes only allowlisted event metadata to a local JSONL file.
# No network requests, credential fields, usernames, command lines, or event messages.
param(
    [string]$OutputPath = "$env:LOCALAPPDATA\AEGIS-AI\windows-events.jsonl",
    [string]$CheckpointPath = "$env:LOCALAPPDATA\AEGIS-AI\windows-events.checkpoint",
    [int]$MaxEvents = 500,
    [int]$LookbackHours = 24
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($MaxEvents -lt 1 -or $MaxEvents -gt 2000) { throw 'MaxEvents must be between 1 and 2000' }
if ($LookbackHours -lt 1 -or $LookbackHours -gt 168) { throw 'LookbackHours must be between 1 and 168' }
$allowedIds = @(4624, 4625, 4672, 4688, 4720, 1102)
$outputFull = [IO.Path]::GetFullPath($OutputPath)
$checkpointFull = [IO.Path]::GetFullPath($CheckpointPath)
if ($outputFull -eq $checkpointFull) { throw 'OutputPath and CheckpointPath must differ' }
foreach ($path in @($outputFull, $checkpointFull)) {
    $directory = Split-Path -Parent $path
    if (-not (Test-Path -LiteralPath $directory)) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }
}
$lastRecord = [long]0
if (Test-Path -LiteralPath $checkpointFull) {
    $checkpointText = (Get-Content -LiteralPath $checkpointFull -Raw).Trim()
    if ($checkpointText -notmatch '^\d+$') { throw 'Invalid checkpoint; refusing to replay or skip events' }
    $lastRecord = [long]::Parse($checkpointText)
}
# Read oldest-first. Each invocation processes at most MaxEvents records and
# resumes at the last written EventRecordID. Unlike newest-first sampling,
# a busy log cannot push older unseen records out of the returned window.
# After the first run, query by record ID instead of a sliding time window:
# a delayed poll must not silently abandon records older than LookbackHours.
try {
    if ($lastRecord -gt 0) {
        $idExpression = ($allowedIds | ForEach-Object { "EventID=$_" }) -join ' or '
        $xpath = "*[System[($idExpression) and EventRecordID > $lastRecord]]"
        $events = @(Get-WinEvent -LogName Security -FilterXPath $xpath -Oldest -MaxEvents $MaxEvents -ErrorAction Stop)
    } else {
        $filter = @{
            LogName = 'Security'
            Id = $allowedIds
            StartTime = (Get-Date).AddHours(-$LookbackHours)
        }
        $events = @(Get-WinEvent -FilterHashtable $filter -Oldest -MaxEvents $MaxEvents -ErrorAction Stop)
    }
} catch [System.Exception] {
    if ($_.Exception.Message -match 'No events were found') {
        Write-Output 'No matching Windows Security events found.'
        return
    }
    throw
}
# Defensive ordering, independent of provider enumeration behavior.
$selected = @($events | Where-Object { [long]$_.RecordId -gt $lastRecord } | Sort-Object RecordId)
if ($selected.Count -eq 0) {
    Write-Output 'No new events since the previous checkpoint.'
    return
}
$lines = foreach ($event in $selected) {
    $record = [ordered]@{
        System = [ordered]@{
            EventID = [int]$event.Id
            Channel = 'Security'
            Computer = [string]$event.MachineName
            EventRecordID = [long]$event.RecordId
            TimeCreated = $event.TimeCreated.ToUniversalTime().ToString('o')
            Provider = [string]$event.ProviderName
        }
        EventData = @{}
    }
    ConvertTo-Json -InputObject $record -Depth 5 -Compress
}
# Append is deliberate: keep local evidence until an explicit, later ingestion step.
# Checkpoint advances only after the file write succeeds. A crash between\n# append and checkpoint may replay events; consumers must deduplicate.
[IO.File]::AppendAllLines($outputFull, [string[]]$lines, [Text.UTF8Encoding]::new($false))
$latest = [long]$selected[-1].RecordId
[IO.File]::WriteAllText($checkpointFull, [string]$latest, [Text.UTF8Encoding]::new($false))
Write-Output ("Exported {0} metadata-only events to {1}. Checkpoint: {2}" -f $selected.Count, $outputFull, $latest)
