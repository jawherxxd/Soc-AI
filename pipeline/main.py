import sys
import time
import signal
from datetime import datetime
from loguru import logger

sys.path.insert(0, '/home/jawher/soc-pipeline')

from layer4.correlator import Correlator
from layer4.llm_analyst import LLMAnalyst
from layer4.case_creator import CaseCreator
from config.settings import settings

# ── Logging setup ────────────────────────────
logger.remove()
logger.add(
    sys.stdout,
    format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | "
           "<level>{level}</level> | {message}",
    level="INFO"
)
logger.add(
    "logs/engine.log",
    rotation="10 MB",
    retention="7 days",
    level="DEBUG"
)

# ── Graceful shutdown ─────────────────────────
running = True

def handle_shutdown(sig, frame):
    global running
    logger.info("Shutdown signal received — stopping engine")
    running = False

signal.signal(signal.SIGINT, handle_shutdown)
signal.signal(signal.SIGTERM, handle_shutdown)

# ── Engine cycle ──────────────────────────────
def run_cycle(correlator, llm, creator) -> dict:
    """
    One full Layer 4 cycle:
    fetch → correlate → analyze → create cases
    Returns stats for this cycle.
    """
    stats = {
        "alerts_fetched": 0,
        "groups_formed": 0,
        "cases_created": 0,
        "false_positives": 0,
        "llm_errors": 0
    }

    try:
        # Step 1 — fetch unprocessed alerts
        alerts = correlator.fetch_unprocessed()
        stats["alerts_fetched"] = len(alerts)

        if not alerts:
            logger.info("No unprocessed alerts — skipping cycle")
            return stats

        # Step 2 — correlate into groups
        groups = correlator.correlate(alerts)
        stats["groups_formed"] = len(groups)

        logger.info(
            f"Processing {len(alerts)} alerts "
            f"in {len(groups)} groups"
        )

        # Step 3 — analyze each group with LLM
        for i, group in enumerate(groups):
            logger.info(
                f"Analyzing group {i+1}/{len(groups)} "
                f"({len(group)} alerts)"
            )

            result = llm.analyze(group)

            if not result:
                stats["llm_errors"] += 1
                logger.warning(f"LLM failed for group {i+1}")
                continue

            if not result.get("is_true_positive"):
                stats["false_positives"] += 1
                logger.info(
                    f"False positive: "
                    f"{result.get('case_title')}"
                )
                continue

            # Step 4 — create case and send to iTop
            case_id = creator.create_case(result, group)

            if case_id:
                stats["cases_created"] += 1
                logger.info(
                    f"Case created: {case_id} | "
                    f"{result['severity']} | "
                    f"{result['case_title']}"
                )

        # Step 5 — mark all alerts as processed
        alert_ids = [a.get("alert_id") for a in alerts]
        correlator.mark_as_processed(alert_ids)

    except Exception as e:
        logger.error(f"Cycle error: {e}")

    return stats


def print_stats(stats: dict, cycle: int, elapsed: float):
    """Print cycle summary."""
    logger.info(
        f"─── Cycle {cycle} summary "
        f"({elapsed:.1f}s) ───"
    )
    logger.info(f"  Alerts fetched:   {stats['alerts_fetched']}")
    logger.info(f"  Groups formed:    {stats['groups_formed']}")
    logger.info(f"  Cases created:    {stats['cases_created']}")
    logger.info(f"  False positives:  {stats['false_positives']}")
    logger.info(f"  LLM errors:       {stats['llm_errors']}")


# ── Main loop ─────────────────────────────────
def main():
    interval = settings.CORRELATION_WINDOW_SECONDS // 5
    # Default: 300s window / 5 = 60s interval

    logger.info("=" * 50)
    logger.info("SOC AI Engine starting")
    logger.info(f"Cycle interval: {interval}s")
    logger.info(f"LLM model: {settings.LLM_MODEL}")
    logger.info(f"iTop: {settings.ITOP_URL}")
    logger.info("=" * 50)

    # Initialize components once
    correlator = Correlator()
    llm = LLMAnalyst()
    creator = CaseCreator()

    cycle = 0

    while running:
        cycle += 1
        start = time.time()

        logger.info(
            f"─── Cycle {cycle} started at "
            f"{datetime.now().strftime('%H:%M:%S')} ───"
        )

        stats = run_cycle(correlator, llm, creator)
        elapsed = time.time() - start
        print_stats(stats, cycle, elapsed)

        if not running:
            break

        # Wait for next cycle
        logger.info(f"Next cycle in {interval}s — press Ctrl+C to stop")
        for _ in range(interval):
            if not running:
                break
            time.sleep(1)

    logger.info("SOC AI Engine stopped cleanly")


if __name__ == "__main__":
    main()
