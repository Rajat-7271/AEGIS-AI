# Read-only Windows workstation preflight for free AEGIS AI staging.
# Does NOT start containers, modify Docker, create credentials, or expose ports.
# Run from PowerShell: powershell -NoProfile -ExecutionPolicy Bypass -File scripts/check_local_staging.ps1
$ErrorActionPreference = "Continue"
Write-Host "AEGIS AI local staging preflight (read-only)"
Write-Host "No containers will be started or modified."
function Show-Check([string]$name, [scriptblock]$check) {
  try { & $check } catch { Write-Host ("{0}: unavailable ({1})" -f $name, $_.Exception.Message) }
}
Show-Check "Memory" {
  $os = Get-CimInstance Win32_OperatingSystem
  $total = [math]::Round($os.TotalVisibleMemorySize / 1MB, 1)
  $free = [math]::Round($os.FreePhysicalMemory / 1MB, 1)
  Write-Host "Installed usable RAM: $total GiB; currently free: $free GiB"
  if ($total -lt 15) { Write-Warning "Less than approximately 16 GiB detected; revise staging budget." }
}
Show-Check "Disk" {
  Get-PSDrive -PSProvider FileSystem | ForEach-Object {
    Write-Host ("Drive {0}: {1:N1} GiB free" -f $_.Name, ($_.Free / 1GB))
  }
}
Show-Check "WSL" {
  if (Get-Command wsl.exe -ErrorAction SilentlyContinue) {
    & wsl.exe --version 2>&1 | Select-Object -First 5
  } else { Write-Host "WSL not detected" }
}
Show-Check "Docker CLI" {
  if (Get-Command docker -ErrorAction SilentlyContinue) {
    & docker --version
    & docker compose version
    & docker info --format 'Server: {{.ServerVersion}}; architecture: {{.Architecture}}; memory bytes: {{.MemTotal}}' 2>&1
  } else { Write-Host "Docker CLI not detected" }
}
Show-Check "Reserved local ports" {
  $ports = @(3000, 5432, 6379, 8000, 8081, 9092)
  $listeners = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
    Where-Object { $ports -contains $_.LocalPort }
  if ($listeners) {
    $listeners | Sort-Object LocalPort | ForEach-Object {
      Write-Host ("Port {0} in use (address {1})" -f $_.LocalPort, $_.LocalAddress)
    }
  } else { Write-Host "No listeners detected on common AEGIS AI ports" }
}
Write-Host "Preflight complete. Review output locally; do not share secrets or full Docker environment dumps."
