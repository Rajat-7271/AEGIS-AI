# Free local staging preparation (Windows, 16 GB RAM)

> Planning document only. Do not deploy, publish a tunnel, provision cloud resources, modify production, or run migrations against a non-disposable database without separate approval.

## Non-negotiable constraints
- Zero hosting fees; no credit/debit card registration.
- Staging is isolated from the existing Vercel, Blitz and Supabase production deployment.
- No production secrets, production database URLs or customer telemetry.
- No public ingress until authentication, access restrictions and rollback are verified.
- All services bind to localhost by default. Never set `AISOC_BIND_ADDR=0.0.0.0` as a shortcut.

## Proposed workstation budget (not measured)
- Windows and background tasks: 4 GiB.
- Docker/WSL2 memory ceiling: start at 9 GiB.
- Remaining headroom: 3 GiB.
- Confirm WSL2 and Docker Desktop resource behavior before applying limits. Docker's WSL2 backend may use a `%UserProfile%\.wslconfig` memory limit; changes affect all WSL2 distros and require `wsl --shutdown` to apply. Back up any existing config; do not overwrite it blindly.
- Avoid local Ollama weights, full-profile OpenSearch, Neo4j and ClickHouse initially. These are not part of the minimum SOC journey.
- Do not assert that 9 GiB is sufficient until peak usage is measured.

## Read-only Windows preflight
From an isolated checkout of this PR branch, run in PowerShell:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/check_local_staging.ps1
```

This checks RAM, disk, WSL, Docker engine availability and common port listeners. It does not start containers, modify settings or connect to production. Review output locally before sharing; avoid pasting any secrets. The script has not been run on the user's Windows machine.

## Prerequisite read-only checks
1. Windows: check installed RAM, available disk (allow for Docker images/volumes), CPU virtualization, WSL version and Docker Desktop availability.
2. Repository: confirm the intended commit SHA and clean isolated checkout/worktree. Do not modify the original Windows repository.
3. Compose: validate the merged configuration with `docker compose -f docker-compose.yml -f docker-compose.prod.yml config --quiet` using a **staging-only** environment file. Note that Compose interpolation can disclose secrets when printing full config; never publish output.
4. Review each image's linux/amd64 compatibility; pin build artifacts to the audited AEGIS AI commit, not upstream GHCR `latest` images.
5. Check free disk, resource limits, and existing port conflicts before starting containers.

## Isolation and security
- Use a distinct Compose project name and distinct staging volumes; existing `container_name` values may conflict with another local stack, so resolve those conflicts before launching.
- Use only generated, staging-specific credentials; check `scripts/ensure_env.py` and `scripts/check_published_secrets.py` behavior on a disposable environment file. Never print credential values.
- For any network-reachable staging use the hardened production overlay: it fixes `ENVIRONMENT=production` and `AISOC_DEV_MODE=0`. The development stack has a demo-admin auth bypass and must never be exposed.
- Restrict web, API and ingest to loopback. TLS and an authenticated gateway are prerequisites for any later public access.
- Use synthetic data; disable or sandbox response actions and external connectors until explicitly authorized.

## Migration and rollback gates
1. Start a fresh, disposable staging PostgreSQL volume, never a production database.
2. Record the schema baseline and apply the migration chain as the migration owner role. Verify the app role is not superuser and RLS is enforced.
3. Test the application against the migrated schema, then back up the staging database.
4. Restore into a second disposable database and verify critical tables, users and cases. Preserve migration logs without credentials.
5. Pin the previous known-good application images and document the switchback procedure. Code rollback does **not** undo SQL migrations; restore or forward-fix schema separately.
6. Do not run `docker compose down -v` on any shared or non-disposable project.

## Validation gates before any deployment approval
- Compose config and preflight secrets pass.
- Backend `/livez` and `/readyz`, frontend page, and same-origin `/api/v1/cases` proxy checks pass.
- Login and role-based access are verified without dev authentication bypass.
- Synthetic event -> ingestion -> detection -> alert -> investigation -> case is demonstrated on the real local stack.
- Peak CPU/RAM/disk measured; no sustained swapping/OOM.
- Backup restore and image rollback tested.
- Explicit approval obtained for any later network exposure or deployment.

## No-card hosting boundary
Local Docker has no cloud-hosting bill, but electricity/internet are not free. Optional Vercel/Cloudflare/Supabase free tiers have usage limits and policies; do not create accounts or assume that any external provider accepts registration without a card. The initial milestone is localhost-only.
