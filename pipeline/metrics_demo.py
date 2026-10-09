#!/usr/bin/env python3
"""
metrics_demo.py — THROWAWAY. Proves the prometheus_client pattern.
Does NOT touch engine.py. Exposes fake pipeline metrics on :9100/metrics
so Prometheus has something to scrape while we build the dashboard.

Run:  python3 metrics_demo.py
Test: curl http://localhost:9100/metrics
Stop: Ctrl-C
"""
import random
import time
from prometheus_client import start_http_server, Counter, Gauge, Histogram

# --- Define metrics ---------------------------------------------------------
# Counter: only ever goes up. Prometheus computes rates from it.
CYCLES_TOTAL = Counter(
    "soc_engine_cycles_total",
    "Total number of completed engine cycles",
)
ALERTS_FETCHED = Counter(
    "soc_alerts_fetched_total",
    "Total alerts fetched from the DB across all cycles",
)
CASES_CREATED = Counter(
    "soc_cases_created_total",
    "Total cases created (true positives)",
)
FPS_SKIPPED = Counter(
    "soc_fps_skipped_total",
    "Total groups classified false positive and skipped",
)
# LLM calls split by outcome via a label — this is what catches an outage.
LLM_REQUESTS = Counter(
    "soc_llm_requests_total",
    "Total LLM requests",
    ["result"],  # result="success" or result="error"
)

# Gauge: can go up or down. Snapshot of "current" state.
LAST_CYCLE_TS = Gauge(
    "soc_engine_last_cycle_timestamp",
    "Unix timestamp of the last completed cycle (for dead-man's switch)",
)

# Histogram: distribution of how long cycles take.
CYCLE_DURATION = Histogram(
    "soc_cycle_duration_seconds",
    "Duration of an engine cycle in seconds",
    buckets=(0.5, 1, 2, 5, 10, 30, 60),
)


def fake_cycle():
    """Simulate one engine cycle with random-but-plausible numbers."""
    with CYCLE_DURATION.time():          # times the block, feeds the histogram
        time.sleep(random.uniform(0.3, 2.0))

        fetched = random.randint(0, 6)
        ALERTS_FETCHED.inc(fetched)

        # Simulate the LLM sometimes failing (like today's outage) ~10% of time
        if random.random() < 0.10:
            LLM_REQUESTS.labels(result="error").inc()
            print(f"[cycle] fetched={fetched}  LLM ERROR (simulated outage)")
        else:
            LLM_REQUESTS.labels(result="success").inc()
            # true positive vs false positive
            if fetched and random.random() < 0.5:
                CASES_CREATED.inc()
                print(f"[cycle] fetched={fetched}  -> case created")
            else:
                FPS_SKIPPED.inc()
                print(f"[cycle] fetched={fetched}  -> FP skipped / nothing")

    CYCLES_TOTAL.inc()
    LAST_CYCLE_TS.set(time.time())


if __name__ == "__main__":
    # Expose /metrics on port 9100 in a background thread.
    start_http_server(9100)
    print("Fake metrics server on :9100  ->  curl http://localhost:9100/metrics")
    print("Simulating an engine cycle every ~5s. Ctrl-C to stop.")
    while True:
        fake_cycle()
        time.sleep(5)
