# Read-only staging health check. Never transmits Windows events.
[CmdletBinding()]
param(
    [string]$Endpoint = 'https://aegis-windows-staging-receiver.onrender.com/v2/health/ready'
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$uri = [Uri]$Endpoint
if ($uri.Scheme -ne 'https' -or $uri.Port -ne 443 -or
    $uri.UserInfo -or $uri.Query -or $uri.Fragment -or
    $uri.AbsolutePath -ne '/v2/health/ready') {
    throw 'Readiness URL must be HTTPS on port 443 with the exact readiness path.'
}
$secret = Read-Host 'Paste the staging token (input hidden)' -AsSecureString
$ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secret)
try {
    $token = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
} finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
}
if ($token.Length -lt 32) { throw 'Token must be at least 32 characters' }
# Windows PowerShell 5.1 needs TLS 1.2 for modern HTTPS gateways.
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
try {
    $result = Invoke-RestMethod -Uri $uri.AbsoluteUri -Method Get -Headers @{
        Authorization = "Bearer $token"
    } -TimeoutSec 120 -MaximumRedirection 0 -ErrorAction Stop
    if ($result.ready -ne $true) { throw 'Staging database not ready' }
    Write-Output 'Staging HTTPS authentication, PostgreSQL connection and v2 table: READY'
} finally {
    Remove-Variable token -ErrorAction SilentlyContinue
}
