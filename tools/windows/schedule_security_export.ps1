# AEGIS AI Windows Security pilot — local automatic export only.
# Creates a scheduled task that periodically runs the local export and offline shipper dry-run pipeline.
# It NEVER invokes the shipper, sends logs, or configures production.
# Requires explicit -Install; default is a no-change preview.
param(
    [switch]$Install,
    [switch]$Remove,
    [ValidateRange(1,60)][int]$IntervalMinutes = 5,
    [string]$TaskName = 'AEGIS-AI-Windows-Security-Export'
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($Install -and $Remove) { throw 'Choose -Install or -Remove, not both.' }
$exporter = Join-Path $PSScriptRoot 'run_security_pipeline.ps1'
if (-not (Test-Path -LiteralPath $exporter)) { throw 'Missing local exporter script.' }
if ($Remove) {
    $existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($null -ne $existing) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-Output "Removed scheduled task $TaskName."
    } else {
        Write-Output "Scheduled task $TaskName does not exist."
    }
    return
}
if (-not $Install) {
    Write-Output "Preview only. Use -Install to schedule local export every $IntervalMinutes minute(s)."
    Write-Output 'This task does not transmit logs or enable production ingestion.'
    return
}
# Read Security channel using the permissions of the current user.
# Task is created only for that user; no SYSTEM account or stored password.
$principal = New-ScheduledTaskPrincipal -UserId ([Security.Principal.WindowsIdentity]::GetCurrent().Name) -LogonType Interactive -RunLevel Limited
$escaped = $exporter.Replace("'", "''")
$command = "& '$escaped'"
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ("-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command " + '"' + $command + '"')
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes $IntervalMinutes)
$settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 4)
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
Write-Output "Installed local-only Windows Security exporter task $TaskName every $IntervalMinutes minute(s)."
Write-Output 'No cloud transmission configured.'
