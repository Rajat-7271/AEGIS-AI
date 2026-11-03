# Agents drain procedure

The drain control is process-local and is intended for a single Agents
container. It rejects all new HTTP work and WebSocket connections after drain
starts, while allowing already admitted requests, response streams, and
FastAPI background tasks to finish. It also stops Kafka triage intake and
waits for accepted Kafka messages, scheduled hunts, the playbook sweeper, and
the investigation reaper to finish their current work.

`AISOC_DRAIN_TOKEN` must be configured for the Agents container. Without it,
the drain endpoints return `503` and no drain can be initiated. The status
response contains aggregate counters and worker states only; it has no tenant,
run, or credential data. Readiness returns `503` while draining.

## Planned maintenance sequence

1. Set a strong `AISOC_DRAIN_TOKEN` in the protected local environment used by
   Compose. Do not put the token in shell history or logs.
2. Start the drain and poll status using the same protected environment:

   ```powershell
   $drainHeaders = @{ "X-AiSOC-Drain-Token" = $env:AISOC_DRAIN_TOKEN }
   Invoke-RestMethod -Method Post -Uri 'http://127.0.0.1:8001/ops/drain?wait_seconds=10' -Headers $drainHeaders
   Invoke-RestMethod -Method Get -Uri 'http://127.0.0.1:8001/ops/drain' -Headers $drainHeaders
   ```

   Repeat the GET until `drained` is `true`. `active` must be empty, every
   `workers` value must be `stopped`, and the service must report
   `draining: true`. A `202`, a timeout, a failed worker, or a nonzero counter
   means **do not stop or recreate Agents**. Keep polling; investigate any
   worker that remains `stopping` or `failed`.
3. Only after the verified status is drained may the operator stop Agents:

   ```powershell
   docker compose stop agents
   ```

   Compose allows up to six minutes for graceful shutdown. The application
   waits up to `AISOC_DRAIN_SHUTDOWN_TIMEOUT_SECONDS` (default 300 seconds)
   for its workers. The Compose grace period is a hard cap, not proof of a
   successful drain; a timeout or forced container exit is not a safe rollout.
4. Before any later image replacement, separately verify a rollback image by
   immutable image ID and source. This drain procedure does not create or
   recover the previously running Agents image.

The ASGI request counter spans the complete request lifetime, including
FastAPI background tasks and streaming responses. The WebSocket counter spans
the handshake through disconnect. Kafka messages are manually committed only
after durable handling; during drain the consumer stops fetching and waits for
its entity lanes. A message interrupted before commit remains eligible for
Kafka replay. A worker that cannot stop cleanly remains `failed` or
`stopping`, and the service never reports itself drained.
