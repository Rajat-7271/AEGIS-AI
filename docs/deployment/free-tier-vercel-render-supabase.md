# Free-Tier Public Deployment (Vercel + Render + Supabase)

₹0/month MVP deployment for a small team. Not for production-scale use.

## Architecture

```
Browser ──► Vercel (Next.js, free)
              │  Server-side rewrites proxy /api/v1/* at the edge
              │
              ├─► /api/v1/* ──────────────► Render Free (FastAPI API)
              │                              └─► Supabase Postgres (free)
              │
              └─► /api/v1/contextual/*
                  /api/v1/playbooks/*
                  /api/v1/hunt/*
                  /api/v1/copilot/* ──────► Render Free (Agents service)
                                           └─► Supabase Postgres (same)
                                           └─► OpenAI API (optional)
```

### Why same-origin proxying (not direct cross-origin)

The frontend's `safeBase()` function in `apps/web/src/lib/api.ts` actively
discards a cross-origin `NEXT_PUBLIC_API_URL` and falls back to `""`
(same-origin). This is a deliberate security measure to prevent CORS issues.
The only working path is Vercel's Next.js server-side rewrites, which proxy
`/api/v1/*` to the Render API URL at the edge. `NEXT_PUBLIC_*` vars must
remain empty so all API calls go through the proxy.

`API_URL` and `AGENTS_URL` are server-side env vars (not `NEXT_PUBLIC_*`),
read by `next.config.js` at build time. They are NOT exposed to the browser.

## What works

- Login, authentication, JWT session management
- User account management (admin + users)
- Alert submission via `POST /api/v1/alerts/submit` (direct to Postgres)
- Alert listing, filtering, triage, escalation, bulk close
- Case management (create, update, close, reopen, comments, timeline)
- Investigation launch and results (reads from Postgres)
- Investigation timeline and event replay
- PDF export of investigation summary (reportlab, pure-Python)
- AI triage and investigation narrative (requires OpenAI API key)
- Onboarding checklist (status reads from DB)

## What is unavailable or degraded

| Feature | Status | Reason |
|---------|--------|--------|
| Kafka event pipeline (ingest → normalize → fuse → alert) | Unavailable | No Kafka, no Go ingest-worker, no fusion service |
| Sigma rule evaluation on incoming events | Unavailable | Lives in fusion service |
| Alert deduplication and correlation | Unavailable | Lives in fusion service (Redis-backed) |
| Risk-Based Alerting entity score accumulation | Unavailable | Lives in fusion service |
| Auto-triage via Kafka consumer | Unavailable | No Kafka; `KAFKA_BOOTSTRAP_SERVERS` empty → worker disabled |
| Real connector polling (EDR, SIEM, cloud) | Unavailable | Requires connectors service + ingest pipeline |
| Push ingest (`POST /v1/ingest/batch`) | Unavailable | Go ingest-worker not deployed |
| Onboarding sample data button | Unavailable | Calls ingest-worker URL that does not exist; returns 502 |
| WebSocket realtime feed | Unavailable | No realtime service; frontend degrades to polling |
| Graph / blast radius (Neo4j) | Unavailable | Neo4j not deployed; API skips at boot |
| Event lake / hunt SQL (ClickHouse) | Unavailable | ClickHouse not deployed |
| Threat intel feeds | Unavailable | threatintel service not deployed |
| Weekly executive digest PDF | Disabled | WeasyPrint too heavy for 512 MB RAM; disabled via env var |
| Login throttle (distributed) | Degraded | No Redis; in-process counter resets on cold start |
| Scheduled report delivery | Disabled | Needs SMTP; disabled via env var |
| Investigation launch after idle | Degraded | First request may 504 (agents cold start ~60s); retry succeeds |
| AI features without OpenAI key | Degraded | Structural results only, no LLM narrative |

## Cold-start behavior & Vercel proxy timeouts

| Scenario | Wait | User experience |
|----------|------|-----------------|
| API sleeping, user opens console | ~45-60s | First request may return 504 while Render wakes; refresh after 30-45s |
| API awake, agents sleeping, start investigation | ~45-60s | First attempt may 504 or timeout; retry succeeds once agents is warm |
| Both awake (normal use) | No delay | Normal performance |
| Supabase paused (7+ days no use) | 10-30s on first query | First API response slow; then normal |

> [!NOTE]
> `experimental.proxyTimeout: 120_000` in `apps/web/next.config.js` governs Next.js's
> standalone Node.js server proxy timeout. On Vercel, requests route through Vercel's
> Edge and Serverless infrastructure where Hobby plan limits apply. If a sleeping Render
> service takes ~50-60 seconds to complete a cold start, Vercel may return a 504 Gateway
> Timeout before the backend finishes initializing. This is expected on the free tier:
> refreshing the page or retrying the operation 30-45 seconds later succeeds once Render is awake.

## Render free-tier budget (750 hours/month)

Two free web services share 750 instance hours per calendar month. Hours
are consumed only while a service is running (not while spun down). At
normal team usage (2-3 hours/day active), both services consume ~180
hours/month — well within budget. Keeping services alive 24/7 via pings
would exhaust the budget in ~15 days.

## Files changed for this deployment

| File | Type | Purpose |
|------|------|---------|
| `services/api/app/main.py` | Modified | One-shot migration gate via `AISOC_RUN_MIGRATIONS_ON_BOOT` |
| `apps/web/vercel.json` | New | Vercel headers for API routes |
| `render-free.yaml` | New | Render Blueprint for API + Agents (free tier) |

No changes to: `docker-compose.yml`, `docker-compose.prod.yml`,
`docker-compose.laptop.yml`, `.env`, `.env.laptop`, or any local
deployment configuration.

## Manual deployment steps

### Step 1: Supabase

1. Create a free project at supabase.com.
2. Go to **Project Settings → Database**.
3. Copy the **Session pooler** connection string (port 5432, session mode).
   Format: `postgresql://postgres.[REF]:[PASS]@aws-0-[region].pooler.supabase.com:5432/postgres`
4. Add `?sslmode=require` to the connection string.
5. Prefix with `postgresql+asyncpg://`.
   Full format:
   `postgresql+asyncpg://postgres.[REF]:[PASS]@aws-0-[region].pooler.supabase.com:5432/postgres?sslmode=require`
6. Use this Session Pooler URL for **both** `DATABASE_URL` and `DATABASE_MIGRATION_URL`.
   *(Crucial: Supabase direct connection `db.[REF].supabase.co` is IPv6-only on the free tier, but Render outbound traffic is IPv4-only. Using the IPv4-compatible Session Pooler on port 5432 ensures Render can connect successfully for both runtime queries and migrations).*

### Step 2: Run migrations

You have two options to apply migrations:

#### Option A: From your Windows laptop using local Docker

The image `ghcr.io/beenuar/aisoc-core-api:laptop-27cb2725c94c` was built locally from commit `27cb2725c94c` and is already present in your local Docker store.

> [!NOTE]
> This command runs without any volume flags (`-v` or `--mount`). It executes in an ephemeral container connected to Supabase over the internet and **does not touch, reset, or modify any local Docker volumes**.
> Note: this tag is local to your machine and is not published to public GHCR.

```powershell
cd C:\Users\rajat\aisoc
docker run --rm `
  -e DATABASE_MIGRATION_URL="postgresql+asyncpg://postgres.[REF]:[PASS]@aws-0-[region].pooler.supabase.com:5432/postgres?sslmode=require" `
  -e AISOC_APP_DB_PASSWORD="[choose a password for aisoc_app role]" `
  ghcr.io/beenuar/aisoc-core-api:laptop-27cb2725c94c `
  python -m app.scripts.run_migrations
```

Verify: check Supabase Table Editor for `aisoc_schema_migrations` table with 135 rows.

#### Option B: Zero-local-Docker via Render boot gate

Render builds the API container directly from the GitHub repository (`./services/api/Dockerfile`).
In `services/api/app/main.py`, a one-shot migration gate is built-in:
1. When deploying `aegis-api` on Render (Step 5), add an environment variable `AISOC_RUN_MIGRATIONS_ON_BOOT=1`.
2. Deploy the service. The API runs all 135 migrations on first boot before starting HTTP listeners.
3. Once the deployment succeeds, remove `AISOC_RUN_MIGRATIONS_ON_BOOT` from the Render dashboard so subsequent cold-start boots skip the migration pass.

### Step 3: Bootstrap admin (one-time)

#### If using your Windows laptop:

```powershell
docker run --rm `
  -e DATABASE_URL="postgresql+asyncpg://postgres.[REF]:[PASS]@aws-0-[region].pooler.supabase.com:5432/postgres?sslmode=require" `
  ghcr.io/beenuar/aisoc-core-api:laptop-27cb2725c94c `
  python -m app.scripts.bootstrap_admin
```

Save the printed password. Login email: `admin@aisoc.internal`.

#### If without local Docker:

You can generate a bcrypt password hash and insert the admin row directly in Supabase SQL Editor:
```sql
-- Insert tenant and admin user directly if bootstrapping without Docker
INSERT INTO tenants (id, name, slug, tier, status)
VALUES ('00000000-0000-0000-0000-000000000001', 'Default', 'default', 'enterprise', 'active')
ON CONFLICT (id) DO NOTHING;
```

### Step 4: Generate secrets (one-time)

Run in PowerShell:
```powershell
python -c "import secrets; print('SECRET_KEY=' + secrets.token_hex(32))"
python -c "import secrets; print('JWT_SECRET=' + secrets.token_hex(32))"
python -c "import secrets; print('METRICS_TOKEN=' + secrets.token_hex(16))"
python -c "import secrets; print('AISOC_SERVICE_TOKEN=' + secrets.token_hex(22))"
python -c "import secrets; print('AISOC_API_SERVICE_TOKEN=' + secrets.token_hex(22))"
python -c "import secrets; print('AISOC_AGENTS_SERVICE_TOKEN=' + secrets.token_hex(22))"
python -c "import secrets; print('REALTIME_INTERNAL_TOKEN=' + secrets.token_hex(16))"
python -c "import secrets; print('AISOC_REALTIME_JWT_SECRET=' + secrets.token_hex(16))"
python -c "from cryptography.fernet import Fernet; print('AISOC_CREDENTIAL_KEY=' + Fernet.generate_key().decode())"
```
*(Note: `REALTIME_INTERNAL_TOKEN` and `AISOC_REALTIME_JWT_SECRET` must be non-empty strings so that `enforce_secure_defaults` in `services/api/app/core/config.py` passes production boot validation).*

### Step 5: Deploy API to Render

1. Go to render.com, create a new Web Service from your GitHub repo.
2. Use `render-free.yaml` as the Blueprint (or configure manually):
   - Docker runtime, context `./services/api`
   - Plan: Free
   - Health check: `/health`
3. Set environment variables (secrets in Render dashboard):
   - `DATABASE_URL`: Supabase session-pooler URL (from step 1)
   - `DATABASE_MIGRATION_URL`: Supabase session-pooler URL (from step 1)
   - All secrets generated in step 4 (including `REALTIME_INTERNAL_TOKEN` and `AISOC_REALTIME_JWT_SECRET`)
   - `AISOC_CORS_ORIGINS`: `https://your-project.vercel.app`
   - `AGENTS_API_URL`: `https://aegis-agents.onrender.com`
   - `AGENTS_SERVICE_URL`: `https://aegis-agents.onrender.com`
   - `AISOC_CONSOLE_URL`: `https://your-project.vercel.app`
   - `OPENAI_API_KEY`: your key (optional)
   - *(Optional if running migrations via Render)*: `AISOC_RUN_MIGRATIONS_ON_BOOT=1`
4. Deploy. The API will start and serve on `https://aegis-api.onrender.com`.

### Step 6: Deploy Agents to Render

1. Create another Web Service from the same repo.
2. Configure:
   - Docker runtime, context `./services/agents`
   - Plan: Free
   - Health check: `/health`
3. Set environment variables:
   - `DATABASE_URL`: same Supabase session-pooler URL
   - `SECRET_KEY`: same as API
   - `AISOC_SERVICE_TOKEN`, `AISOC_API_SERVICE_TOKEN`,
     `AISOC_AGENTS_SERVICE_TOKEN`: same as API
   - `API_SERVICE_URL`: `https://aegis-api.onrender.com`
   - `AISOC_API_URL`: `https://aegis-api.onrender.com`
   - `API_URL`: `https://aegis-api.onrender.com`
   - `OPENAI_API_KEY`: same as API (optional)
4. Deploy.

### Step 7: Deploy frontend to Vercel

1. Go to vercel.com, import your GitHub repo.
2. Set **Root Directory** to `apps/web`.
3. Vercel auto-detects Next.js and pnpm monorepo.
4. Set environment variables (server-side, not `NEXT_PUBLIC_*`):
   - `API_URL`: `https://aegis-api.onrender.com`
   - `AGENTS_URL`: `https://aegis-agents.onrender.com`
5. Do NOT set any `NEXT_PUBLIC_API_URL` or `NEXT_PUBLIC_AGENTS_URL`
   (they must remain empty for same-origin proxying to work).
6. Deploy.

### Step 8: Verify

1. Open `https://your-project.vercel.app`.
2. Login with `admin@aisoc.internal` and the password from step 3.
3. Navigate to Alerts — should show empty state (no alerts yet).
4. Submit a test alert via API:
   ```powershell
   $token = "<JWT from login>"
   Invoke-RestMethod -Uri "https://aegis-api.onrender.com/api/v1/alerts/submit" `
     -Method POST -Headers @{Authorization="Bearer $token"; "X-Tenant-Id"="00000000-0000-0000-0000-000000000001"; "Content-Type"="application/json"} `
     -Body '{"events":[{"eventType":"test","displayMessage":"Test alert"}]}'
   ```
5. Refresh Alerts — should show the test alert.
6. Create a case from the alert.
7. Launch an investigation (may need a retry if agents is cold).
8. Export the investigation PDF.

### Step 9: Handling Supabase 7-day inactivity pause

Free Supabase projects pause after 7 consecutive days without any database queries.
**Do NOT use external 14-minute ping services (e.g. UptimeRobot) against Render.**
Render's free tier shares a 750 hours/month pool across all free web services in the workspace. Pinging Render continuously 24/7 consumes 720+ hours and exhausts the entire monthly quota in ~15 days, suspending all services. Furthermore, `/health` is in-memory and does not query the database.

To keep Supabase active at ₹0/month:
1. Normal team use (logging into the console or submitting an alert once a week) resets the 7-day inactivity timer automatically.
2. Alternatively, enable Supabase's built-in `pg_cron` extension in the Supabase Dashboard (**Database → Extensions → pg_cron**) and schedule a daily lightweight query directly inside Postgres:
   ```sql
   SELECT cron.schedule('keep-alive', '0 0 * * *', 'SELECT 1');
   ```
   This runs entirely inside Postgres at zero cost and without consuming Render instance hours.
3. If Supabase does pause after a period of vacation or inactivity, click **Restore project** in the Supabase Dashboard (takes ~15-30 seconds).
