# Offline runtime regression: mock Get-WinEvent, use disposable files only.
# No Windows Security log reads, network calls, or production files.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$exporter = Join-Path $PSScriptRoot 'export-security-events.ps1'
$root = Join-Path ([IO.Path]::GetTempPath()) ("aegis-export-recovery-" + [guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($root) | Out-Null
$script:mockNewest = 100
$script:mockQueryCalls = 0
function Get-WinEvent {
    param([string]$LogName, [int]$MaxEvents, [string]$ErrorAction,
          [string]$FilterXPath, [hashtable]$FilterHashtable, [switch]$Oldest)
    if ($MaxEvents -eq 1 -and -not $Oldest) {
        return [pscustomobject]@{ RecordId = $script:mockNewest }
    }
    $script:mockQueryCalls++
    throw 'Unexpected query: safety guard should stop first'
}
function Assert-Stops {
    param([string]$Name, [string]$Expected, [string]$OutputPath, [string]$CheckpointPath)
    $before = [IO.File]::ReadAllBytes($OutputPath)
    $checkpointBefore = [IO.File]::ReadAllText($CheckpointPath)
    $script:mockQueryCalls = 0
    $caught = $null
    try {
        & $exporter -OutputPath $OutputPath -CheckpointPath $CheckpointPath -MaxEvents 25
    } catch { $caught = $_.Exception.Message }
    if (-not $caught -or -not $caught.Contains($Expected)) {
        throw "$Name failed: unexpected result '$caught'"
    }
    if ($script:mockQueryCalls -ne 0) { throw "$Name failed: attempted event pagination" }
    if (-not [Linq.Enumerable]::SequenceEqual([byte[]]$before, [byte[]][IO.File]::ReadAllBytes($OutputPath))) {
        throw "$Name failed: output changed"
    }
    if ([IO.File]::ReadAllText($CheckpointPath) -ne $checkpointBefore) {
        throw "$Name failed: checkpoint changed"
    }
}
try {
    $out = Join-Path $root 'events.jsonl'
    $cp = Join-Path $root 'checkpoint.txt'
    [IO.File]::WriteAllText($cp, '40')
    [IO.File]::WriteAllText($out, '{"System":{"EventRecordID":41}}' + [Environment]::NewLine)
    Assert-Stops 'tail_ahead' 'Possible interrupted checkpoint write' $out $cp

    [IO.File]::WriteAllText($out, '{"System":' + [Environment]::NewLine)
    Assert-Stops 'malformed_tail' 'export JSONL tail is invalid' $out $cp

    [IO.File]::WriteAllText($out, '{"System":{"EventRecordID":40}}' + [Environment]::NewLine)
    $script:mockNewest = 39
    Assert-Stops 'log_regression' 'Possible log clear/reset' $out $cp

    @{status='passed'; checks=3; mocked_event_log=$true;
      files_unchanged=$true; network_requests=0; real_events_sent=0} |
        ConvertTo-Json -Compress
} finally {
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}
