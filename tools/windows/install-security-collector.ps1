# Register an opt-in current-user collector. Setup never starts collection/upload.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$PythonPath,
    [Parameter(Mandatory=$true)][string]$DeviceId,
    [string]$StateDirectory = "$env:LOCALAPPDATA\AEGIS-AI\security-v2",
    [switch]$EnableUpload,
    [string]$Endpoint = ''
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$taskName = 'AEGIS-Windows-Security-Staging'
if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) { throw 'Task already exists; preserve its state and review before replacing' }
if ($DeviceId -cnotmatch '^[A-Za-z0-9._-]{1,128}$') { throw 'Invalid device ID' }
$python = (Resolve-Path -LiteralPath $PythonPath).Path
$directory = [IO.Path]::GetFullPath($StateDirectory)
if (Test-Path -LiteralPath $directory) { throw 'Use a new state directory; preserve existing evidence' }
if ($EnableUpload) {
    $uri = [Uri]$Endpoint
    if ($uri.Scheme -ne 'https' -or $uri.Port -ne 443 -or $uri.UserInfo -or $uri.Query -or $uri.Fragment -or $uri.AbsolutePath -ne '/v2/windows-security/events') {
        throw 'Expected the staging HTTPS v2 ingestion URL on port 443'
    }
}
New-Item -ItemType Directory -Path $directory | Out-Null
$identity = [Security.Principal.WindowsIdentity]::GetCurrent().Name
$acl = Get-Acl -LiteralPath $directory
$acl.SetAccessRuleProtection($true, $false)
foreach ($who in @($identity, 'NT AUTHORITY\SYSTEM')) {
    $rule = [Security.AccessControl.FileSystemAccessRule]::new($who, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
    $acl.AddAccessRule($rule)
}
Set-Acl -LiteralPath $directory -AclObject $acl
$config = @{python=$python; device=$DeviceId; spool=(Join-Path $directory 'spool.sqlite'); send=[bool]$EnableUpload; endpoint=$Endpoint}
if ($EnableUpload) {
    $secret = Read-Host 'Staging device token (DPAPI encrypted for this Windows user)' -AsSecureString
    if ($secret.Length -lt 32) { throw 'Token must have at least 32 characters' }
    ConvertFrom-SecureString $secret | Set-Content -LiteralPath (Join-Path $directory 'token.dpapi') -Encoding ASCII
}
$configPath = Join-Path $directory 'collector.json'
$config | ConvertTo-Json | Set-Content -LiteralPath $configPath -Encoding UTF8
$env:AEGIS_WINDOWS_DEVICE_ID = $DeviceId
& $python (Join-Path $PSScriptRoot 'collector.py') --spool $config.spool --initialize
if ($LASTEXITCODE -ne 0) { throw 'Source initialization failed; task was not installed' }
$launcher = Join-Path $PSScriptRoot 'run-security-collector.ps1'
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -NonInteractive -File `"$launcher`" -ConfigPath `"$configPath`""
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $identity
$settings = New-ScheduledTaskSettingsSet -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -MultipleInstances IgnoreNew -ExecutionTimeLimit ([TimeSpan]::Zero) -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
$principal = New-ScheduledTaskPrincipal -UserId $identity -LogonType Interactive -RunLevel Limited
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal -ErrorAction Stop | Out-Null
Write-Output 'Registered AEGIS-Windows-Security-Staging. Start explicitly with Start-ScheduledTask. Runs only while this user is logged in.'
