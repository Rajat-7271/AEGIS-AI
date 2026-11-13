# Read-only local readiness summary for the Windows Security staging pilot.
# Does not upload events, create source epochs, or modify checkpoints.
[CmdletBinding()]
param(
    [string]$DataDirectory = (Join-Path $env:LOCALAPPDATA 'AEGIS-AI')
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$continuityScript = Join-Path $PSScriptRoot 'check-security-log-continuity.ps1'
$eventsFile = Join-Path $DataDirectory 'windows-events.jsonl'
$checkpointFile = Join-Path $DataDirectory 'windows-events.upload.checkpoint'
$last = [long]0
if (Test-Path -LiteralPath $checkpointFile -PathType Leaf) {
    $raw = (Get-Content -LiteralPath $checkpointFile -Raw).Trim()
    if ($raw -notmatch '^[0-9]+$') {
        throw 'Invalid upload checkpoint; refusing to proceed'
    }
    $last = [long]::Parse($raw)
}
$observation = & $continuityScript -LastRecordId $last | ConvertFrom-Json
$exportCount = 0
if (Test-Path -LiteralPath $eventsFile -PathType Leaf) {
    $exportCount = @(Get-Content -LiteralPath $eventsFile).Count
}
[pscustomobject]@{
    SecurityChannel = $observation.Channel
    NewestRecordId = $observation.NewestRecordId
    UploadCheckpoint = $last
    ExportedLines = $exportCount
    ClearEventsSinceCheckpoint = $observation.ClearEventsSinceCheckpoint
    TrustedLogInstanceEstablished = $observation.TrustedLogInstanceEstablished
    SafeToEnableUnattendedV2 = $false
    NextStep = 'Manual verification of durable Security log instance identity required'
} | ConvertTo-Json -Depth 3
