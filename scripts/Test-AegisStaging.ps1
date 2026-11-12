#Requires -Version 7.2
<#
.SYNOPSIS
Read-only validation of the default local AEGIS staging profile.
.DESCRIPTION
Requires Docker Desktop (Linux), Compose with !override support, and Python 3.
Use -ConfigOnly to validate without querying the daemon or Windows port and RAM
state. A config-only run reports a warning for the skipped live checks.
Exit codes: 0 pass, 1 fail, 2 warnings require review.
#>
param([switch]$ConfigOnly)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$project = 'aegis-stage'
$docker = @('--context', 'desktop-linux')
$files = @('docker-compose.yml', 'docker-compose.prod.yml', 'docker-compose.staging.yml',
    'docker-compose.staging-build.yml', 'docker-compose.staging-isolation.yml')
$compose = $docker + @('compose', '--project-directory', $root, '-p', $project,
    '--env-file', (Join-Path $root '.env'))
foreach ($file in $files) { $compose += @('-f', (Join-Path $root $file)) }
$results = [System.Collections.Generic.List[string]]::new()

function Report($level, $check, $message) {
    $results.Add($level)
    Write-Host "[$level] $check - $message"
}

function Read-Captured($program, [string[]]$arguments, $inputJson = '') {
    $start = [Diagnostics.ProcessStartInfo]::new((Get-Command "$program.exe" -CommandType Application | Select-Object -First 1).Source)
    $start.WorkingDirectory = $root
    $start.UseShellExecute = $false
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.RedirectStandardInput = $true
    $start.StandardInputEncoding = [Text.UTF8Encoding]::new($false)
    # Keep inherited credentials, Compose profiles, and Docker overrides out of the child.
    $start.Environment.Clear()
    foreach ($name in 'SystemRoot', 'WINDIR', 'PATH', 'USERPROFILE', 'LOCALAPPDATA', 'APPDATA', 'TEMP', 'TMP') {
        $value = [Environment]::GetEnvironmentVariable($name)
        if ($value) { $start.Environment[$name] = $value }
    }
    $start.Environment['AISOC_REPO_ROOT'] = $root
    $start.Environment['COMPOSE_PROFILES'] = ''
    foreach ($argument in $arguments) { $start.ArgumentList.Add($argument) }
    $process = [Diagnostics.Process]::Start($start)
    try {
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if ($inputJson) { $process.StandardInput.Write($inputJson) }
        $process.StandardInput.Close()
        $process.WaitForExit()
        [void] $stderr.GetAwaiter().GetResult()
        if ($process.ExitCode -ne 0) { throw 'Read-only subprocess failed.' }
        $stdout.GetAwaiter().GetResult().Trim()
    } finally {
        $process.Dispose()
    }
}

function Read-Docker([string[]]$arguments) {
    Read-Captured docker ($docker + $arguments)
}

try {
    foreach ($file in $files + '.env') {
        $item = Get-Item -LiteralPath (Join-Path $root $file) -Force
        if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw 'Compose inputs must be regular staging files.'
        }
    }
    $model = Read-Captured docker ($compose + @('config', '--no-env-resolution', '--format', 'json')) | ConvertFrom-Json -AsHashtable
    $services = $model.services
    $preflight = $services['preflight-secrets']
    if (!$preflight -or !$services.web) { throw 'Required staging services are missing.' }
    Report PASS Compose "Default profile resolves with $($services.Count) services."
} catch {
    Report FAIL Compose 'Could not resolve staging inputs. Check staging .env, Compose support, and file access. Raw diagnostics are suppressed.'
    exit 1
}

$dependencyProblems = foreach ($entry in $services.GetEnumerator()) {
    $dependencies = $entry.Value.depends_on ?? @{}
    if ($entry.Key -ne 'preflight-secrets' -and
        ($dependencies['preflight-secrets'].condition -ne 'service_completed_successfully' -or
         $dependencies['preflight-secrets'].required -eq $false)) { $entry.Key }
    foreach ($edge in $dependencies.GetEnumerator()) {
        $target = $services[$edge.Key]
        if (!$target -or ($edge.Value.condition -eq 'service_healthy' -and
            (!$target.healthcheck.test -or $target.healthcheck.disable -or $target.healthcheck.test[0] -eq 'NONE'))) { $entry.Key }
    }
}
$mount = @($preflight.volumes | Where-Object {
    $_.type -eq 'bind' -and $_.target -ceq '/repo' -and $_.read_only -and $_.source -eq $root
})
if ($dependencyProblems -or $preflight.depends_on -or $preflight.restart -ne 'no' -or
    ($preflight.entrypoint -join ' ') -cne 'python3 /repo/scripts/check_published_secrets.py --check-env' -or
    $preflight.environment.AISOC_REPO_ROOT -cne '/repo' -or $mount.Count -ne 1) {
    Report FAIL Dependencies 'Dependency or preflight wiring differs from the staging contract.'
} else {
    Report PASS Dependencies 'All services wait for one-shot preflight. Health-gated dependencies have probes.'
}
$pending = [System.Collections.Generic.Queue[string]]::new()
$seen = [System.Collections.Generic.HashSet[string]]::new()
$pending.Enqueue('web')
while ($pending.Count) {
    $name = $pending.Dequeue()
    if ($seen.Add($name)) {
        foreach ($dependency in $services[$name].depends_on.Keys) { $pending.Enqueue($dependency) }
    }
}
$smoke = @($seen | Sort-Object)
$expectedSmoke = 'api, kafka, postgres, preflight-secrets, realtime, redis, web, zookeeper'
if (($smoke -join ', ') -cne $expectedSmoke) {
    Report FAIL 'Web smoke scope' 'The web dependency set differs from the documented eight-service smoke test.'
}
$webEnvironment = $services.web.environment
if ($webEnvironment.API_URL -cne 'http://api:8000' -or $webEnvironment.REALTIME_URL -cne 'http://realtime:4000') {
    Report FAIL 'Web smoke routing' 'The console must proxy API and realtime requests to their staging services.'
}

$pythonCheck = @"
import contextlib
import io
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, "scripts")
from check_published_secrets import COMPOSE_REQUIRED_RE, _check_env, offending, published_literals

data = json.load(sys.stdin)
environments = data["environments"]
preflight = environments["preflight-secrets"]
published = published_literals()
with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
    os.environ.update({key: value for key, value in preflight.items()
                       if key != "AISOC_REPO_ROOT" and value is not None})
    actual = _check_env()
    os.environ["POSTGRES_PASSWORD"] = next(iter(published))
    negative = _check_env()
lines = [line for name in data["files"]
         for line in Path(name).read_text(encoding="utf-8").splitlines()]
required = {key for line in lines if not line.lstrip().startswith("#")
            for key in COMPOSE_REQUIRED_RE.findall(line)}
missing = sum(not (preflight.get(key) or "").strip() for key in required)
smoke_hits, other_hits = 0, 0
for name, env in environments.items():
    hits = len(offending(env or {}, published))
    if name in data["smoke"]:
        smoke_hits += hits
    else:
        other_hits += hits
print(json.dumps(dict(actual=actual, negative=negative, missing=missing,
                      smoke_hits=smoke_hits, other_hits=other_hits)))
"@
try {
    $environments = [ordered]@{}
    foreach ($name in $services.Keys) { $environments[$name] = $services[$name].environment }
    $inputJson = ConvertTo-Json @{ environments = $environments; smoke = $smoke; files = $files } -Depth 10 -Compress
    $verdict = Read-Captured python @('-B', '-X', 'utf8', '-c', $pythonCheck) $inputJson | ConvertFrom-Json -AsHashtable
    if ($verdict.actual -ne 0 -or $verdict.negative -ne 1 -or $verdict.missing -or $verdict.smoke_hits) {
        Report FAIL Secrets "Credential validation failed. Missing preflight variables: $($verdict.missing). Published-default matches in smoke services: $($verdict.smoke_hits)."
    } else {
        Report PASS Secrets 'Preflight and web smoke credentials passed. The published-default negative control was rejected.'
    }
    if ($verdict.other_hits) {
        Report WARN 'Other service secrets' "$($verdict.other_hits) published-default matches outside the web smoke scope."
    }
} catch {
    Report FAIL Secrets 'Could not run the repository credential checker with Python 3. Raw diagnostics are suppressed.'
}

$isolationProblems = @(
    foreach ($key in $model.networks.Keys) {
        $network = $model.networks[$key]
        if ($key -notin 'default', 'aisoc' -or !$network.internal -or $network.external -or
            $network.name -ne ($project + '_' + $key) -or ($network.driver -and $network.driver -ne 'bridge')) { $key }
    }
    foreach ($entry in $services.GetEnumerator()) {
        $service = $entry.Value
        if ($service.container_name -notlike 'aegis-stage-*' -or
            $service.network_mode -or !$service.networks -or $service.privileged -or
            $service.volumes_from -or $service.env_file -or
            ($service.networks.Keys | Where-Object { !$model.networks.Contains($_) })) { $entry.Key }
        foreach ($bind in $service.volumes | Where-Object type -eq 'bind') {
            if (!$bind.read_only -or ($bind.source -ne $root -and
                !$bind.source.StartsWith("$root\", [StringComparison]::OrdinalIgnoreCase) -and
                !$bind.source.StartsWith("$root/", [StringComparison]::OrdinalIgnoreCase))) { $entry.Key }
        }
    }
    foreach ($key in $model.volumes.Keys) {
        $volume = $model.volumes[$key]
        if ($volume.external -or $volume.name -ne ($project + '_' + $key) -or $volume.driver_opts -or
            ($volume.driver -and $volume.driver -ne 'local')) { $key }
    }
)
if ($model.name -ne $project -or $model.networks.Count -ne 2 -or $isolationProblems) {
    Report FAIL Isolation 'Unexpected project, network, mount, or volume configuration.'
} else {
    Report PASS Isolation 'Both networks are internal. Named storage is project-scoped and staging bind mounts are read-only.'
}

$published = @(foreach ($entry in $services.GetEnumerator()) {
    foreach ($port in $entry.Value.ports) {
        "$($entry.Key)|$($port.host_ip)|$($port.published)|$($port.target)|$($port.protocol)"
    }
})
if ($published.Count -ne 1 -or $published[0] -cne 'web|127.0.0.1|3200|3000|tcp') {
    Report FAIL Ports 'The sole permitted publish is web on 127.0.0.1:3200/tcp.'
} else {
    Report PASS Ports 'Only web publishes a port, on 127.0.0.1:3200/tcp.'
}

$localImages = @{
    api = 'aegis-stage-api:local'; web = 'aegis-stage-web:local'
    realtime = 'aegis-stage-realtime:local'; 'ingest-worker' = 'aegis-stage-ingest:local'
    'preflight-secrets' = 'aegis-stage-api:local'
}
$unsafePolicy = @($localImages.Keys | Where-Object {
    $service = $services[$_]
    !$service -or $service.image -cne $localImages[$_] -or $service.pull_policy -ne 'never'
})
if ($unsafePolicy) {
    Report FAIL 'Image policy' "Local-only image policy or tag mismatch for $($unsafePolicy -join ', ')."
} else {
    Report PASS 'Image policy' 'Migration services and preflight use local staging tags with pull policy never.'
}

$ollamaModel = 'llama3.2:3b-instruct-q4_K_M'
$ollamaGate = $services['ollama-pull']
$gateway = $services.litellm
$ollamaMount = @($services.ollama.volumes | Where-Object {
    $_.type -eq 'volume' -and $_.source -ceq 'ollama_data' -and $_.target -ceq '/root/.ollama'
})
if (($ollamaGate.entrypoint -join ' ') -cne "ollama show $ollamaModel" -or
    $ollamaGate.environment.OLLAMA_HOST -cne 'http://ollama:11434' -or
    $ollamaGate.depends_on.ollama.condition -ne 'service_healthy' -or
    ($gateway.depends_on ?? @{})['ollama-pull'].condition -ne 'service_completed_successfully' -or
    ($gateway.depends_on ?? @{})['ollama-pull'].required -eq $false -or
    $gateway.environment.AISOC_LLM_API_BASE -cne 'http://ollama:11434' -or
    $gateway.environment.AISOC_LLM_MODEL_FAST -cne "ollama_chat/$ollamaModel" -or
    $gateway.environment.AISOC_LLM_MODEL_DEEP -cne "ollama_chat/$ollamaModel" -or
    $services.ollama.environment.OLLAMA_NOPRUNE -ne 'true' -or
    ($services.ollama.environment.OLLAMA_MODELS -and
     $services.ollama.environment.OLLAMA_MODELS -cne '/root/.ollama/models') -or $ollamaMount.Count -ne 1) {
    Report FAIL 'Ollama cache gate' 'The full stack must use the pinned model through the local Ollama cache gate.'
} else {
    Report PASS 'Ollama cache gate' 'LiteLLM waits for a local model check. The cache contents require a separate runtime check.'
}

Write-Host "Web smoke dependency set: $($smoke -join ', ')"
if ($ConfigOnly) {
    Report WARN 'Live checks' 'Skipped Docker inventory and Windows listener, reservation, and RAM checks.'
    if ($results -contains 'FAIL') { exit 1 }
    exit 2
}

try {
    $listeners = [Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().GetActiveTcpListeners()
    $excludedPorts = Read-Captured netsh @('interface', 'ipv4', 'show', 'excludedportrange', 'protocol=tcp')
    $reserved = foreach ($line in $excludedPorts -split '\r?\n') {
        if ($line -match '^\s*(\d+)\s+(\d+)\s*\*?\s*$' -and
            [int]$Matches[1] -le 3200 -and [int]$Matches[2] -ge 3200) { $true }
    }
    if ($listeners.Port -contains 3200) {
        Report FAIL 'Windows port' 'TCP 3200 already has a Windows listener.'
    } elseif ($reserved) {
        Report FAIL 'Windows port' 'TCP 3200 is in a Windows excluded port range.'
    } else {
        Report PASS 'Windows port' 'TCP 3200 has no listener or reservation.'
    }
} catch {
    Report FAIL 'Windows port' 'Could not inspect Windows TCP listeners or reservations.'
}

try {
    $endpoint = Read-Docker @('context', 'inspect', 'desktop-linux', '--format', '{{.Endpoints.docker.Host}}')
    if ($endpoint -ne 'npipe:////./pipe/dockerDesktopLinuxEngine') { throw 'Unexpected Docker endpoint.' }
    $os, $bytes = (Read-Docker @('info', '--format', '{{.OSType}}|{{.MemTotal}}')) -split '\|', 2
    if ($os -ne 'linux' -or [long]$bytes -le 0) { throw 'Unexpected Docker engine.' }
    $rows = (Read-Docker @('ps', '-a', '--format', '{{.Names}}|{{.Label "com.docker.compose.project"}}|{{.Ports}}')) -split '\r?\n'
    $planned = @($services.Values | ForEach-Object container_name)
    $existing = @()
    $conflicts = @()
    foreach ($row in $rows) {
        $name, $owner, $ports = $row -split '\|', 3
        if ($owner -eq $project) { $existing += $name }
        if (($name -in $planned -and $owner -ne $project) -or
            ($owner -ne $project -and $ports -match ':3200->')) { $conflicts += $name }
    }
    $networkNames = (Read-Docker @('network', 'ls', '--format', '{{.Name}}')) -split '\r?\n'
    $existingNetworks = @($model.networks.Values | Where-Object { $_.name -in $networkNames })
    foreach ($network in $existingNetworks) {
        $details = Read-Docker @('network', 'inspect', $network.name, '--format',
            '{{.Internal}}|{{.Driver}}|{{index .Labels "com.docker.compose.project"}}|{{range .Containers}}{{.Name}} {{end}}')
        $internal, $driver, $owner, $members = $details -split '\|', 4
        if ($internal -ne 'true' -or $driver -ne 'bridge' -or $owner -ne $project -or
            ($members -split ' ' | Where-Object { $_ -and $_ -notin $existing })) { $conflicts += $network.name }
    }
    $volumeNames = (Read-Docker @('volume', 'ls', '--format', '{{.Name}}')) -split '\r?\n'
    $existingVolumes = @($model.volumes.Values | Where-Object { $_.name -in $volumeNames })
    foreach ($volume in $existingVolumes) {
        $details = Read-Docker @('volume', 'inspect', $volume.name, '--format',
            '{{.Driver}}|{{index .Labels "com.docker.compose.project"}}|{{len .Options}}')
        if ($details -ne "local|$project|0") { $conflicts += $volume.name }
    }
    if ($conflicts) {
        Report FAIL 'Docker resources' 'A container name, port, network, or volume conflicts with staging.'
    } elseif ($existing -or $existingVolumes -or $existingNetworks) {
        Report WARN 'Docker resources' 'Existing staging resources require review before reuse.'
    } else {
        Report PASS 'Docker resources' 'No staging container, network, volume, or Docker port collisions.'
    }

    $cache = (Read-Docker @('image', 'ls', '--format', '{{.Repository}}:{{.Tag}}')) -split '\r?\n'
    $missingSmoke = @($smoke | Where-Object { $services[$_].image -notin $cache })
    $missingCore = @($services.Keys | Where-Object { $services[$_].image -notin $cache -and $_ -notin $smoke })
    if ($missingSmoke) {
        Report FAIL Images "Local smoke images missing for $($missingSmoke -join ', ')."
    } elseif ($missingCore) {
        Report WARN Images "Smoke images present. Other default-profile images missing for $($missingCore -join ', ')."
    } else {
        Report PASS Images 'All default-profile service image tags are present locally.'
    }

    $windows = Get-CimInstance Win32_OperatingSystem
    $freeMiB = [math]::Floor($windows.FreePhysicalMemory / 1024)
    $engineGiB = [math]::Round([long]$bytes / 1GB, 2)
    # Conservative review thresholds for the dependency smoke, not measured minimum requirements.
    $status = if ($freeMiB -lt 2048 -or [long]$bytes -lt 8GB) { 'WARN' } else { 'PASS' }
    Report $status RAM "Windows free: $freeMiB MiB. Docker capacity: $engineGiB GiB. Review thresholds: 2048 MiB free and 8 GiB capacity."
    if ('aegis-stage_ollama_data' -notin $volumeNames) {
        Report WARN 'Full default stack' 'The staging Ollama volume is absent. Seed it before a full start.'
    } else {
        Report WARN 'Full default stack' 'The staging Ollama volume exists. Its model contents are unverified.'
    }
} catch {
    Report FAIL 'Docker or host checks' 'Could not complete Docker inventory or Windows RAM checks. Verify Docker Desktop and permissions.'
}

if ($results -contains 'FAIL') { exit 1 }
if ($results -contains 'WARN') { exit 2 }
exit 0
