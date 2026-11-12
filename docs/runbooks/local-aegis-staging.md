# Local AEGIS staging smoke test

Run these steps in the staging worktree on Windows with PowerShell 7.2 or later
and Docker Desktop's Linux engine.

## Read-only checks

```powershell
Set-Location (git rev-parse --show-toplevel)
pwsh -NoProfile -File .\scripts\Test-AegisStaging.ps1
python -B -m unittest discover -s tests -p test_staging_validator.py -v
```

The validator returns 1 on failure and 2 when warnings need review. Use
`-ConfigOnly` to check Compose without Docker inventory or Windows listener,
port reservation, and RAM checks. A successful config-only run returns 2
because those checks were skipped. The regression suite runs the real Compose
merge with synthetic credentials in temporary directories.

Before the web smoke, resolve any failures and recheck RAM and TCP 3200. The
validator uses 2 GiB of free Windows RAM and an 8 GiB Docker memory ceiling as
planning thresholds. A missing Ollama cache affects the full stack only.

## Approved container smoke test

Get explicit approval before running either phase. Start with a fresh staging
project and run the setup in a disposable PowerShell process. It clears
inherited variables so the staging .env supplies Compose settings. Keep
resolved Compose output, container environments, and raw startup logs private.

```powershell
Set-Location (git rev-parse --show-toplevel)
$keep = 'SystemRoot', 'WINDIR', 'PATH', 'USERPROFILE', 'LOCALAPPDATA', 'APPDATA', 'TEMP', 'TMP'
$docker = (Get-Command docker.exe -CommandType Application | Select-Object -First 1).Source
Get-ChildItem Env: | Where-Object Name -NotIn $keep | ForEach-Object {
    [Environment]::SetEnvironmentVariable($_.Name, $null, 'Process')
}
$env:COMPOSE_PROFILES = ''
$stage = @(
    '--context', 'desktop-linux', 'compose', '--project-directory', (Get-Location).Path,
    '-p', 'aegis-stage', '--env-file', '.env',
    '-f', 'docker-compose.yml', '-f', 'docker-compose.prod.yml',
    '-f', 'docker-compose.staging.yml', '-f', 'docker-compose.staging-build.yml',
    '-f', 'docker-compose.staging-isolation.yml'
)
$endpoint = & $docker --context desktop-linux context inspect desktop-linux --format '{{.Endpoints.docker.Host}}'
if ($LASTEXITCODE -ne 0 -or $endpoint -ne 'npipe:////./pipe/dockerDesktopLinuxEngine') {
    throw 'Expected the local Docker Desktop Linux endpoint.'
}
```

1. **Preflight only.** Require exit 0. The command can create the staging
   default network and removes the one-off container on exit.

   ```powershell
   & $docker @stage run --rm --no-deps --pull never -T preflight-secrets
   if ($LASTEXITCODE -ne 0) { throw 'Staging preflight failed.' }
   ```

2. **Web and its dependencies.** The web target also starts API, realtime,
   Kafka, ZooKeeper, Postgres, Redis, and the regular preflight service. Require
   startup success, preflight exit 0 in the service status listing, and HTTP
   200 from all probes. The API readiness route is probed inside the API
   container. Probe web liveness and the realtime proxy inside the web
   container. Docker can omit the requested host binding on internal-only
   networks. [Docker internal bridge port behavior](https://github.com/moby/moby/discussions/53256)

   ```powershell
   & $docker @stage up -d --no-build --pull never --no-recreate --wait --wait-timeout 180 web
   if ($LASTEXITCODE -ne 0) { throw 'Staging web startup failed.' }
   & $docker @stage ps -a
   & $docker @stage exec -T api python -c "import urllib.request; assert urllib.request.urlopen('http://127.0.0.1:8000/readyz', timeout=5).status == 200"
   if ($LASTEXITCODE -ne 0) { throw 'Staging API is not ready.' }
   foreach ($path in '/api/health', '/api/v1/realtime/healthz') {
       $response = Invoke-WebRequest -NoProxy -Uri "http://127.0.0.1:3200$path" -TimeoutSec 5
       if ($response.StatusCode -ne 200) { throw "Unexpected smoke response for $path." }
   }
   ```

On failure, record the step and use separately approved staging cleanup.

## Hosted smoke test

The Actions job runs for draft PR #18's staging branch on a disposable
Ubuntu runner. It generates fresh credentials in runner temp storage and
builds only API, web, and realtime. Preflight reuses the API image. The job
pulls the four datastore images before startup and checks headroom before
building and again before starting the stack. The gates require 6 GiB
available RAM and 8 GiB free Docker storage for the build, then 4 GiB RAM
and 3 GiB free Docker storage for startup. These are planning floors.

Only the eight-service web dependency set starts. The job checks internal
network membership, resource ownership, API readiness, web liveness, and
the realtime proxy. It records allowlisted container states and HTTP
results. Cleanup runs after failure as well as success and removes
containers, networks, and volumes carrying the unique CI project label.
The runner discards the local images at the end of the job.

## Prepare the Ollama cache offline

The web smoke has no Ollama dependency. For a full staging start, seed the
llama3.2:3b-instruct-q4_K_M model for Ollama 0.6.7. This version fetches a
registry manifest on every pull, even when the blobs are cached. The staging
service named ollama-pull uses ollama show against the internal daemon. LiteLLM
waits for that check and uses the same model for both routes.
[Ollama 0.6.7 pull implementation](https://github.com/ollama/ollama/blob/v0.6.7/server/images.go)

1. On an approved connected non-production source using the same Ollama
   version, acquire and verify the exact tag. Export a tar archive with the
   relative paths models/manifests and models/blobs and every blob the model
   manifest references. Include only model data from the .ollama directory.
   Record the model digest and the archive SHA-256 on the source.
   [Ollama 0.6.7 model directory](https://github.com/ollama/ollama/blob/v0.6.7/envconfig/config.go)
2. Transfer the archive to the staging worktree through an approved offline
   path. Compare Get-FileHash -Algorithm SHA256 with the trusted source
   checksum. Before extraction, verify the archive has only relative paths
   under models/, contains no path traversal or link entries, and includes all
   manifest-referenced blobs with matching SHA-256 digests.
3. With separate approval, confirm staging Ollama is absent and create a new
   aegis-stage_ollama_data volume with Compose labels. Use a cached helper with
   no networking and a read-only archive mount. The following commands assume
   the clean shell above and a verified ollama-models.tar in the worktree.
   [Docker volume restore](https://docs.docker.com/engine/storage/volumes/#restore-volume-from-a-backup)

   ```powershell
   $engine = @('--context', 'desktop-linux')
   $volumes = & $docker @engine volume ls --format '{{.Name}}'
   if ($LASTEXITCODE -ne 0 -or 'aegis-stage_ollama_data' -in $volumes) {
       throw 'Expected a new staging Ollama volume.'
   }
   $archive = (Resolve-Path -LiteralPath .\ollama-models.tar).Path
   $create = @(
       'volume', 'create', '--driver', 'local',
       '--label', 'com.docker.compose.project=aegis-stage',
       '--label', 'com.docker.compose.volume=ollama_data', 'aegis-stage_ollama_data'
   )
   & $docker @engine @create
   if ($LASTEXITCODE -ne 0) { throw 'Could not create the staging Ollama volume.' }
   $import = @(
       'run', '--rm', '--pull', 'never', '--network', 'none',
       '--mount', "type=bind,source=$archive,target=/seed.tar,readonly",
       '--mount', 'type=volume,source=aegis-stage_ollama_data,target=/cache,volume-nocopy',
       '--entrypoint', '/bin/sh', 'postgres:16-alpine',
       '-ec', 'test -z "$(ls -A /cache)"; tar -xf /seed.tar -C /cache'
   )
   & $docker @engine @import
   if ($LASTEXITCODE -ne 0) { throw 'Import failed. Review the staging volume before retrying.' }
   ```

4. During a separately approved Ollama check, start only staging Ollama and
   its preflight dependency, then run the one-shot local model check. Require
   exit 0 before allowing LiteLLM to start. If inference is in scope, issue one
   small local request to verify the weights load. The read-only validator
   checks volume presence. Cache contents and inference require runtime checks.

   ```powershell
   & $docker @stage up -d --no-build --pull never --no-recreate --wait --wait-timeout 180 ollama
   if ($LASTEXITCODE -ne 0) { throw 'Staging Ollama startup failed.' }
   & $docker @stage run --rm --no-deps --pull never -T ollama-pull
   if ($LASTEXITCODE -ne 0) { throw 'The pinned model is unavailable in the staging cache.' }
   ```
