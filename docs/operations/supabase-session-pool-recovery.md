# Supabase session-pool exhaustion: Copilot recovery runbook

## Observed incident (2026-11-13)

The Agents service returned HTTP 500 on `POST /api/v1/copilot/chat` and
`GET /api/v1/copilot/conversations`. The traceback pointed to
`services/agents/app/api/conversation_store.py`, where
`asyncpg.create_pool()` raised
`(EMAXCONNSESSION) max clients reached in session mode - pool_size: 15`.
This is a database connection failure, **not evidence that OpenRouter failed**.
Read-only Supabase activity initially showed 15 idle `Supavisor` sessions;
a later snapshot showed they had cleared. Neither snapshot attributes all
connections to a particular application.

## Scope of proposed code change

PR #56 reduces each of three Agents asyncpg pools (Copilot, hunt, ledger)
from max 4 to max 1, min 1 to min 0, and sets a 30-second inactive lifetime.
Initialization is serialized with an asyncio lock to avoid duplicate pools
during concurrent first requests. These are **per-process** limits, not a
global cap across services or replicas.

The API uses SQLAlchemy `create_async_engine` and reads
`DATABASE_POOL_SIZE` and `DATABASE_MAX_OVERFLOW` from environment
(overridable defaults: 20 and 10). The defaults alone could permit up to 30
connections **per API process**. Do not change global defaults blindly:
other deployments may need higher throughput.

## Pre-deployment approval gate

1. Confirm the number of API and Agents processes/replicas in Blitz, and
   inventory any other DB-using services sharing the same Supabase session
   pooler. Check the **actual** deployed API pool environment overrides.
2. Compute a conservative upper bound:
   `API_processes * (DATABASE_POOL_SIZE + DATABASE_MAX_OVERFLOW) +
   Agents_processes * 3 + other_connection_consumers`.
   The proposed `DATABASE_POOL_SIZE=3` and `DATABASE_MAX_OVERFLOW=1`
   is only a **candidate** for a single API process, not a proven safe
   setting for arbitrary worker counts. Leave headroom below the observed
   15-session limit for other clients and monitoring.
3. Confirm CI on the exact commit, especially Copilot guard regression,
   tenant isolation, and API database-pool tests. Test parallel Copilot
   chat/history requests against a disposable staging DB with an equivalent
   connection limit. Verify persisted conversation history and tenant scope.
4. Record the current live image/revision and nonsecret environment setting
   values for rollback. Obtain explicit approval before any deployment or
   production environment changes. Never log or copy credentials.

## Controlled rollout (only after explicit approval)

1. Apply approved API pool environment overrides if needed. Avoid restarting
   unrelated production services; verify worker/replica counts first.
2. Roll out the Agents code to the existing Agents service only, using the
   approved revision. If API settings change, perform a separately controlled
   API rollout. Preserve production data and schema.
3. Use an authenticated, low-impact Copilot question (e.g. `hello`) and
   check that one request produces one model call and a real response. Test
   conversation history and a second simultaneous chat/history request.
4. Read-only monitor `pg_stat_activity` session counts and Agents/API logs.
   Watch for `EMAXCONNSESSION`, pool timeouts, HTTP 500, and unexpected
   response latency. Do not terminate DB sessions to make a test pass.
5. Stop rollout and roll back the specific service/config change if Copilot
   errors increase, history fails, tenant isolation regresses, or unrelated
   API endpoints degrade. Recheck session counts after rollback.

## Read-only SQL diagnostic

```sql
SELECT application_name, usename, state, count(*)::int AS connections
FROM pg_stat_activity
WHERE datname = current_database()
GROUP BY 1, 2, 3
ORDER BY connections DESC;
```

This reports database backends; it cannot on its own identify all clients
behind Supavisor or prove how many distinct application processes exist.

## Important limitations

A passing unit test and 35 green GitHub workflows are not proof of live
capacity. No production Copilot recovery or real provider call is verified
by this PR. Keep the PR draft and production unchanged until approved.
