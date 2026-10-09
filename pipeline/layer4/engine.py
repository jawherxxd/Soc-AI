"""
Layer 4 - Main Engine Scheduler
===============================
Runs the AI analysis cycle on a fixed interval:

    fetch unprocessed alerts          (Correlator)
        -> correlate into groups      (Correlator)
        -> analyze each group         (LLMAnalyst)
        -> create a case for true positives (CaseCreator)
        -> mark the fetched alerts as processed (Correlator)

Run it as its OWN process, separate from the webhook:

    cd ~/soc-pipeline
    source venv/bin/activate
    python3 -m layer4.engine

Stop it with Ctrl+C (or SIGTERM from a process manager / systemd).

Prometheus metrics are exposed on http://<host>:9100/metrics for scraping.
"""

import os
import sys
import signal
import time
from datetime import datetime

# --- Make the project importable no matter how the script is launched -------
# engine.py lives in <project_root>/layer4/, so the project root is two levels up.
# This mirrors the sys.path trick from your manual Layer 4 test.
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from loguru import logger
from apscheduler.schedulers.blocking import BlockingScheduler
from prometheus_client import start_http_server, Counter, Gauge, Histogram

from layer4.correlator import Correlator
from layer4.llm_analyst import LLMAnalyst
from layer4.case_creator import CaseCreator

# --- Configuration ----------------------------------------------------------
# How often the analysis cycle runs, in seconds.
# Kept as a constant for now; you can promote it to .env/settings.py later
# (e.g. ENGINE_INTERVAL_SECONDS) to match your config-driven style.
ENGINE_INTERVAL_SECONDS = 60

# Port where this process exposes its /metrics endpoint for Prometheus.
METRICS_PORT = 9100

# --- Prometheus metrics -----------------------------------------------------
# Defined ONCE at module level (unlike the DB connections, which are per-cycle
# on purpose). Counters only ever increase; Prometheus computes rates from them.
CYCLES_TOTAL = Counter(
    "soc_engine_cycles_total",
    "Total number of engine cycles that ran (including idle cycles)",
)
ALERTS_FETCHED = Counter(
    "soc_alerts_fetched_total",
    "Total unprocessed alerts fetched from the DB across all cycles",
)
GROUPS_CORRELATED = Counter(
    "soc_groups_correlated_total",
    "Total correlated groups produced across all cycles",
)
CASES_CREATED = Counter(
    "soc_cases_created_total",
    "Total cases created (true positives)",
)
FPS_SKIPPED = Counter(
    "soc_fps_skipped_total",
    "Total groups classified as false positive and skipped",
)
# LLM outcome split by label. The result="error" series is the outage detector.
LLM_REQUESTS = Counter(
    "soc_llm_requests_total",
    "Total LLM analysis attempts, split by outcome",
    ["result"],  # "success" | "error"
)
# Gauge: current snapshot. now() - this = dead-man's switch.
LAST_CYCLE_TS = Gauge(
    "soc_engine_last_cycle_timestamp",
    "Unix timestamp of the last cycle that completed (dead-man's switch)",
)
# Histogram: distribution of full-cycle durations.
CYCLE_DURATION = Histogram(
    "soc_cycle_duration_seconds",
    "Wall-clock duration of a full engine cycle in seconds",
    buckets=(0.5, 1, 2, 5, 10, 30, 60, 120),
)

# --- Logging ----------------------------------------------------------------
# loguru already prints to the console by default. Add a rotating file sink
# under the logs/ folder you already created.
logger.add(
    os.path.join(PROJECT_ROOT, "logs", "engine.log"),
    rotation="10 MB",      # start a new file once it reaches 10 MB
    retention="7 days",    # delete logs older than a week
    level="INFO",
    enqueue=True,          # stays safe if you later run cycles in threads
)

def run_cycle() -> None:
    """One full Layer 4 pass.

    Designed to NEVER crash the scheduler: any error is logged and the next
    cycle simply tries again.
    """
    # Time the whole cycle (feeds the duration histogram). The `finally` block
    # below guarantees the heartbeat metrics update on EVERY cycle - including
    # the early-return "no alerts" path - so the dead-man's switch stays honest
    # during idle periods instead of falsely looking like a dead engine.
    cycle_start = time.time()
    try:
        # Open fresh connections every cycle. This is the key fix for the
        # "SSL connection has been closed unexpectedly" / "connection already
        # closed" errors: a connection that goes stale while idle can never
        # poison future cycles, because nothing is kept open between cycles.
        # At a 60s interval the reconnect overhead is negligible.
        correlator = Correlator()
        llm = LLMAnalyst()
        creator = CaseCreator()

        alerts = correlator.fetch_unprocessed()

        if not alerts:
            logger.info("Cycle: no unprocessed alerts, nothing to do.")
            return

        ALERTS_FETCHED.inc(len(alerts))

        groups = correlator.correlate(alerts)
        GROUPS_CORRELATED.inc(len(groups))
        logger.info(
            f"Cycle: {len(alerts)} alert(s) grouped into {len(groups)} group(s)."
        )

        cases_created = 0
        false_positives = 0
        analysis_errors = 0

        for index, group in enumerate(groups, start=1):
            try:
                result = llm.analyze(group)

                # analyze() returns None if the LLM call or JSON parse failed.
                if not result:
                    analysis_errors += 1
                    LLM_REQUESTS.labels(result="error").inc()
                    logger.warning(f"Group {index}: LLM returned no result, skipping.")
                    continue

                LLM_REQUESTS.labels(result="success").inc()

                # create_case() already skips false positives and returns None
                # for them; a real case_id is returned for true positives.
                case_id = creator.create_case(result, group)

                if case_id:
                    cases_created += 1
                    CASES_CREATED.inc()
                    logger.success(
                        f"Group {index}: case {case_id} created "
                        f"[severity={result.get('severity')}] "
                        f"{result.get('case_title')}"
                    )
                else:
                    false_positives += 1
                    FPS_SKIPPED.inc()
                    logger.info(
                        f"Group {index}: classified as false positive "
                        f"({result.get('false_positive_reason', 'no reason given')})."
                    )

            except Exception:
                # One bad group must not stop the rest of the cycle.
                analysis_errors += 1
                LLM_REQUESTS.labels(result="error").inc()
                logger.exception(f"Group {index}: unexpected error during analysis.")
                continue

        # Mark every fetched alert as processed so it is not picked up again.
        #
        # NOTE: this matches your tested manual flow. The trade-off is that
        # alerts whose group hit an LLM/network error are ALSO marked done and
        # will not be retried. If you later want retries on transient failures,
        # collect only the alert_ids of successfully-analysed groups and mark
        # just those instead (we can do that once we confirm your group shape).
        correlator.mark_as_processed([a["alert_id"] for a in alerts])

        logger.info(
            f"Cycle complete: {cases_created} case(s) created, "
            f"{false_positives} false positive(s), {analysis_errors} error(s)."
        )

    except Exception:
        # fetch / correlate / mark itself failed: log and let the next cycle
        # retry. Because nothing was marked, no alerts are lost here.
        logger.exception("Cycle failed before completion; will retry next interval.")

    finally:
        # Heartbeat: runs on EVERY cycle path (success, idle early-return, or
        # error). This is what keeps the dead-man's switch accurate.
        CYCLES_TOTAL.inc()
        LAST_CYCLE_TS.set(time.time())
        CYCLE_DURATION.observe(time.time() - cycle_start)


def main() -> None:
    logger.info(
        f"Starting Layer 4 engine - running every {ENGINE_INTERVAL_SECONDS}s. "
        "Press Ctrl+C to stop."
    )

    # Expose Prometheus metrics on :9100 in a background thread BEFORE the
    # scheduler blocks. start_http_server is non-blocking (own daemon thread),
    # so it will not interfere with APScheduler.
    start_http_server(METRICS_PORT)
    logger.info(f"Prometheus metrics available on :{METRICS_PORT}/metrics")

    scheduler = BlockingScheduler()
    scheduler.add_job(
        run_cycle,
        trigger="interval",
        seconds=ENGINE_INTERVAL_SECONDS,
        max_instances=1,                # never run two cycles at once
        coalesce=True,                  # if cycles back up, collapse to one
        misfire_grace_time=30,          # tolerate small scheduling delays
        next_run_time=datetime.now(),   # run one cycle IMMEDIATELY on startup
        id="layer4_cycle",
    )

    # Graceful shutdown for Ctrl+C and `kill` / systemd (SIGTERM).
    def _shutdown(signum, frame):
        logger.warning(f"Received signal {signum}, shutting down engine...")
        scheduler.shutdown(wait=False)
        sys.exit(0)

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    try:
        scheduler.start()
    except (KeyboardInterrupt, SystemExit):
        logger.info("Engine stopped.")


if __name__ == "__main__":
    main()
