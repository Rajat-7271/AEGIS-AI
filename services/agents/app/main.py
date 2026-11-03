import asyncio
import os
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app._health import install_health_routes, register_subscription
from app.api.contextual import router as contextual_router
from app.api.copilot import router as copilot_router
from app.api.drain import router as drain_router
from app.api.explain import router as explain_router
from app.api.hunt_search import router as hunt_search_router
from app.api.hunts import router as hunts_router
from app.api.investigate import router as investigate_router
from app.api.metrics import router as metrics_router
from app.api.playbooks import router as playbook_router
from app.api.playbooks import verifications_router as playbook_verifications_router
from app.api.playbooks import waits_router as playbook_waits_router
from app.api.replay_router import router as replay_router
from app.api.router import router
from app.api.triage import router as triage_router
from app.core.telemetry import instrument_app
from app.drain import DrainMiddleware, drain_controller, run_drain_workers

# Wave 3. Imported so the quality metrics have a production importer:
# tool selection, evidence completeness and time to verdict had zero
# hits anywhere in the tree, and a metric nothing imports is a module.
from app.eval import score_agent_quality

# Re-exported rather than left as a bare import: an import with a
# `noqa` and no reader is indistinguishable from a stale one, and
# CodeQL reads it as unused. `__all__` states the intent.
__all__ = ["score_agent_quality"]
from app.hunt import scheduler as hunt_scheduler
from app.hunt import store as hunt_store
from app.investigator import ledger as investigation_ledger
from app.investigator import run_reaper as investigation_run_reaper
from app.llm.factory import preflight_llm
from app.playbook import PlaybookStore
from app.playbook import sweeper as playbook_sweeper
from app.tools.mitre_full import embed_techniques_into_qdrant, load_attck_corpus
from app.workers.business_context import BusinessContextApplier
from app.workers.business_context import is_enabled as business_context_enabled
from app.workers.fused_alert_consumer import FusedAlertTriageWorker, worker_enabled

logger = structlog.get_logger()


def _log_triage_worker_exit(task: asyncio.Task) -> None:
    """Report the auto-triage worker's exit instead of losing it in the task."""
    if task.cancelled():
        logger.info("auto_triage_worker.cancelled")
        return
    exc = task.exception()
    if exc is None:
        logger.error("auto_triage_worker.exited", detail="consume loop returned; fused alerts are no longer triaged")
        return
    logger.error("auto_triage_worker.died", error=str(exc), error_type=type(exc).__name__, exc_info=exc)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Load resources on startup."""
    await drain_controller.reset()
    app.state.drain_task = None
    app.state.drain_stoppers = {}
    # Seed playbook store with default templates
    try:
        store = PlaybookStore.default()
        n = store.seed_defaults()
        if n:
            logger.info("playbook_store.seeded", count=n)
    except Exception as exc:
        logger.warning("Playbook store seed failed", error=str(exc))

    # Wave 1 — surface an unroutable LLM gateway/alias config at boot instead of
    # silently degrading to heuristics on the first (400ing) live call.
    for warning in preflight_llm():
        logger.warning("llm_preflight", detail=warning)

    # Load full MITRE ATT&CK corpus
    try:
        await load_attck_corpus()
    except Exception as exc:
        logger.warning("MITRE ATT&CK corpus load failed at startup", error=str(exc))

    # Embed into Qdrant for RAG (only if configured)
    qdrant_url = os.getenv("QDRANT_URL", "")
    openai_key = os.getenv("OPENAI_API_KEY", "")
    if qdrant_url and openai_key:
        try:
            await embed_techniques_into_qdrant(
                qdrant_url=qdrant_url,
                openai_api_key=openai_key,
            )
        except Exception as exc:
            logger.warning("ATT&CK Qdrant embedding skipped", error=str(exc))

    # Warm up the investigation-ledger pool. This is best-effort: if the DB is
    # unreachable we keep running, ledger writes just become no-ops.
    try:
        await investigation_ledger.get_pool()
    except Exception as exc:  # noqa: BLE001
        logger.warning("investigation_ledger.warmup_failed", error=str(exc))

    # Start the continuous hunt scheduler (Wave 2 — w2-hac). Gated by env
    # so dev/CI runs that don't want background jobs can opt out via
    # AISOC_HUNT_SCHEDULER_DISABLE=1. Best-effort: a corpus load failure
    # or DB outage must not block API startup.
    if os.getenv("AISOC_HUNT_SCHEDULER_DISABLE", "").strip() not in ("1", "true", "yes"):
        try:
            await hunt_scheduler.start_scheduler()
            if hunt_scheduler.get_scheduler().running:
                app.state.drain_stoppers["hunt_scheduler"] = hunt_scheduler.drain_scheduler
                await drain_controller.set_worker("hunt_scheduler", "running")
            else:
                await drain_controller.set_worker("hunt_scheduler", "stopped")
        except Exception as exc:  # noqa: BLE001
            await drain_controller.set_worker("hunt_scheduler", "failed")
            logger.warning("hunt.scheduler.start_failed", error=str(exc))
    else:
        await drain_controller.set_worker("hunt_scheduler", "stopped")

    # Phase B1 — auto-triage every fused alert off the Kafka stream (copilot:
    # read-only triage, no response dispatch). Off unless KAFKA_BOOTSTRAP_SERVERS
    # is set; degrades to deterministic triage without an LLM key.
    app.state.triage_worker = None
    app.state.triage_worker_task = None
    if worker_enabled():
        try:
            # Phase B4 — environment-specific noise reduction (post-fusion →
            # pre-triage). Enabled by default; needs a rules file to do anything.
            applier = BusinessContextApplier() if business_context_enabled() else None
            triage_worker = FusedAlertTriageWorker(
                bootstrap_servers=os.environ["KAFKA_BOOTSTRAP_SERVERS"],
                topic=os.getenv("KAFKA_TOPIC_ALERTS_FUSED", "aisoc.alerts.fused"),
                business_context=applier,
            )
            app.state.triage_worker = triage_worker
            task = asyncio.create_task(triage_worker.start())
            # Same pair as fusion and ueba: retrieve the task's outcome so a
            # dead worker is in the log, and make readiness depend on the
            # subscription rather than on this block having run. Without the
            # probe, /readyz answered 200 for a worker whose loop had exited —
            # and nothing auto-triages a fused alert after that.
            task.add_done_callback(_log_triage_worker_exit)
            app.state.triage_worker_task = task
            register_subscription(app, triage_worker.topic, lambda: triage_worker.attached)
            app.state.drain_stoppers["kafka_triage"] = lambda: _stop_kafka_worker(app)
            await drain_controller.set_worker("kafka_triage", "running")
            logger.info("auto_triage_worker.enabled")
        except Exception as exc:  # noqa: BLE001 — never block API startup
            await drain_controller.set_worker("kafka_triage", "failed")
            logger.warning("auto_triage_worker.start_failed", error=str(exc))
    else:
        await drain_controller.set_worker("kafka_triage", "stopped")

    # Depth 5.3 — wake timer waits and expire pauses nobody decided.
    # `pause.expire_due` had been written and never called from production,
    # so an undecided approval sat `waiting` forever; a `wait` step inherits
    # that and turns it into a run that stops and never continues.
    app.state.playbook_sweeper_task = None
    try:
        sweeper_task = playbook_sweeper.start(app)
        if sweeper_task is not None:
            app.state.drain_stoppers["playbook_sweeper"] = lambda: playbook_sweeper.stop(app)
            await drain_controller.set_worker("playbook_sweeper", "running")
        else:
            await drain_controller.set_worker("playbook_sweeper", "stopped")
    except Exception as exc:  # noqa: BLE001 — never block API startup
        await drain_controller.set_worker("playbook_sweeper", "failed")
        logger.warning("playbook_sweeper.start_failed", error=str(exc))

    # Issue #1242 — close investigation runs orphaned by a process that died.
    # The wall-clock deadline on the manual path only ends a run whose process
    # is still alive; the run store is a module dict, so a restart leaves the
    # `investigation_runs` row at 'running' with nothing left to finish it.
    app.state.investigation_reaper_task = None
    try:
        reaper_task = investigation_run_reaper.start(app)
        if reaper_task is not None:
            app.state.drain_stoppers["investigation_reaper"] = lambda: investigation_run_reaper.stop(app)
            await drain_controller.set_worker("investigation_reaper", "running")
        else:
            await drain_controller.set_worker("investigation_reaper", "stopped")
    except Exception as exc:  # noqa: BLE001 — never block API startup
        await drain_controller.set_worker("investigation_reaper", "failed")
        logger.warning("investigation_run_reaper.start_failed", error=str(exc))

    async def _stop_drain_workers() -> None:
        failures: list[str] = []
        for name, stop_worker in app.state.drain_stoppers.items():
            await drain_controller.set_worker(name, "stopping")
            try:
                await stop_worker()
            except Exception as exc:  # noqa: BLE001 — continue, then fail closed
                failures.append(name)
                await drain_controller.set_worker(name, "failed")
                logger.error("drain.worker_stop_failed", worker=name, error=str(exc))
            else:
                await drain_controller.set_worker(name, "stopped")
        if failures:
            raise RuntimeError(f"background workers failed to drain: {', '.join(failures)}")

    app.state.stop_drain_workers = _stop_drain_workers

    # Phase 2.6 — flip /readyz to 200 once startup work is done.
    app.state.mark_ready()

    yield

    # Close admission, stop background workers gracefully, and wait for the
    # request/stream counters before releasing their shared database pools.
    await drain_controller.begin()
    app.state.mark_not_ready()
    drain_task = getattr(app.state, "drain_task", None)
    if drain_task is None:
        drain_task = asyncio.create_task(run_drain_workers(app))
        app.state.drain_task = drain_task
    shutdown_timed_out = False
    try:
        timeout = float(os.getenv("AISOC_DRAIN_SHUTDOWN_TIMEOUT_SECONDS", "300"))
        async with asyncio.timeout(timeout):
            await asyncio.shield(drain_task)
            if not await drain_controller.wait_drained(timeout):
                raise TimeoutError
    except TimeoutError:
        shutdown_timed_out = True
        logger.critical("drain.shutdown_timeout", timeout_seconds=timeout)
    except Exception as exc:  # noqa: BLE001
        shutdown_timed_out = True
        logger.critical("drain.shutdown_failed", error=str(exc))

    snapshot = await drain_controller.snapshot()
    if shutdown_timed_out or not snapshot["drained"]:
        logger.critical("drain.incomplete_at_shutdown", active=snapshot["active"], workers=snapshot["workers"])
    else:
        try:
            await hunt_store.close_pool()
        except Exception as exc:  # noqa: BLE001
            logger.warning("hunt.store.close_failed", error=str(exc))
        try:
            await investigation_ledger.close_pool()
        except Exception as exc:  # noqa: BLE001
            logger.warning("investigation_ledger.close_failed", error=str(exc))


async def _stop_kafka_worker(app: FastAPI) -> None:
    worker = getattr(app.state, "triage_worker", None)
    task = getattr(app.state, "triage_worker_task", None)
    if worker is None:
        return
    await worker.stop()
    if task is not None:
        await task


app = FastAPI(
    title="AiSOC Agent Orchestrator",
    description="LangGraph-based autonomous investigation and response agents",
    version="0.1.0",
    lifespan=lifespan,
)

# Phase 2.6 — k8s liveness + readiness probes (see app/_health.py).
# /readyz returns 503 until the lifespan startup finishes touching
# MITRE, Qdrant, ledger pool, and the hunt scheduler.
_mark_ready, _mark_not_ready = install_health_routes(app, service_name="aisoc-agents")
app.state.mark_ready = _mark_ready
app.state.mark_not_ready = _mark_not_ready
register_subscription(app, "drain", lambda: not drain_controller.draining)

# CORS — the web console talks to this service directly (it does not go through
# the Next.js rewrite layer for agent endpoints because we want to stream
# NDJSON without buffering through the proxy). Origins are resolved via the
# shared ``build_cors_kwargs`` helper which reads AISOC_CORS_ORIGINS (canonical)
# / CORS_ORIGINS (legacy) and enforces the "no wildcard with credentials in
# production" invariant so a careless ``export CORS_ORIGINS=*`` can't ship
# CSRF to prod.
from app.core.cors import build_cors_kwargs  # noqa: E402

app.add_middleware(
    CORSMiddleware,
    **build_cors_kwargs(service_name="agents", allow_credentials=True),
)

# OpenTelemetry auto-instrumentation (FastAPI + httpx)
instrument_app(app)
app.add_middleware(DrainMiddleware, controller=drain_controller)

# Unprefixed: Prometheus scrapes /metrics, not /api/v1/metrics, and the
# scrape config is shared shape across services.
app.include_router(metrics_router)
app.include_router(drain_router)
app.include_router(router, prefix="/api/v1")
app.include_router(investigate_router)  # prefix already set in investigate.py
app.include_router(triage_router)  # prefix: /api/v1  (POST /cases/{id}/triage — router topology, T2.2)
app.include_router(playbook_router)
app.include_router(playbook_waits_router)  # prefix: /api/v1/playbook-waits
app.include_router(playbook_verifications_router)  # prefix: /api/v1/playbook-verifications
app.include_router(contextual_router)  # prefix: /api/v1/contextual
app.include_router(hunts_router)  # prefix: /api/v1/hunts
app.include_router(hunt_search_router)  # prefix: /api/v1/hunt  (search + saved)
app.include_router(copilot_router)  # prefix: /api/v1/copilot
app.include_router(explain_router)  # prefix: /api/v1  (POST /explain — NDJSON stream)
# Gap-closure Phase 1.4: POST /api/v1/replay/run. The runner shipped in 1.2
# with no caller; this is what the API's evaluation job drives.
app.include_router(replay_router, prefix="/api/v1")


@app.get("/health")
async def health():
    from app.tools.mitre_full import get_coverage_summary

    summary = get_coverage_summary()
    return {
        "status": "healthy",
        "service": "aisoc-agents",
        "attck_corpus": summary,
    }
