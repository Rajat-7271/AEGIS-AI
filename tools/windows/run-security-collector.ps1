[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$ConfigPath)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
try {
    $config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
    $env:AEGIS_WINDOWS_DEVICE_ID = $config.device
    $arguments = @((Join-Path $PSScriptRoot 'collector.py'), '--spool', $config.spool, '--continuous')
    if ($config.send) {
        $encrypted = (Get-Content -LiteralPath (Join-Path (Split-Path -Parent $ConfigPath) 'token.dpapi') -Raw).Trim()
        $secret = ConvertTo-SecureString $encrypted
        $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secret)
        try { $env:AEGIS_WINDOWS_STAGING_TOKEN = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr) }
        finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr) }
        $env:AEGIS_WINDOWS_STAGING_ENDPOINT = $config.endpoint
        $arguments += '--send'
    }
    $log = Join-Path (Split-Path -Parent $ConfigPath) 'collector-status.log'
    & $config.python @arguments 2>&1 | ForEach-Object {
        if ((Test-Path -LiteralPath $log) -and (Get-Item -LiteralPath $log).Length -gt 1048576) {
            Move-Item -LiteralPath $log -Destination "$log.previous" -Force
        }
        $_ | Out-File -LiteralPath $log -Append -Encoding UTF8
    }
    $collectorExit = $LASTEXITCODE
} catch {
    # Never include exception text, tokens, DSNs or source payloads.
    Write-Output 'Collector stopped; inspect source continuity, permissions and local status.'
    $collectorExit = 1
} finally {
    Remove-Item Env:AEGIS_WINDOWS_STAGING_TOKEN -ErrorAction SilentlyContinue
}
exit $collectorExit
