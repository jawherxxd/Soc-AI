from fastapi import FastAPI, Request, HTTPException
from loguru import logger
import uvicorn
import sys
import os

sys.path.insert(0, '/home/jawher/soc-pipeline')

from layer3.normalizer import Normalizer
from layer3.enricher import Enricher
from layer3.cleaner import Cleaner
from layer3.db_writer import DBWriter
from config.settings import settings
from api.feedback import router as feedback_router

# Prometheus: auto HTTP metrics + custom business counters
from prometheus_fastapi_instrumentator import Instrumentator
from prometheus_client import Counter

# Initialize FastAPI app
app = FastAPI(
    title="SOC AI Pipeline",
    description="Wazuh alert ingestion and enrichment",
    version="1.0.0"
)
app.include_router(feedback_router)

# --- Prometheus custom Layer 3 metrics --------------------------------------
# The auto-instrumentator (below) counts HTTP requests/latency/status for free.
# These counters capture the DOMAIN events the HTTP layer can't see: how many
# alerts were received, actually stored, or dropped as noise/duplicate.
# The gap between "received" and "stored" is what silently broke ingestion
# before - now it is a visible metric.
ALERTS_RECEIVED = Counter(
    "soc_l3_alerts_received_total",
    "Total alerts received on the /alert webhook",
)
ALERTS_STORED = Counter(
    "soc_l3_alerts_stored_total",
    "Total alerts written to the enriched_alerts table",
)
ALERTS_DROPPED = Counter(
    "soc_l3_alerts_dropped_total",
    "Total alerts received but NOT stored (noise / duplicate)",
)
ALERTS_FAILED = Counter(
    "soc_l3_alerts_failed_total",
    "Total alerts that raised an error during processing",
)

# Auto-instrument all endpoints (request count, latency histogram, status codes)
# and expose the combined /metrics endpoint on this same app (port 8000).
Instrumentator().instrument(app).expose(app, endpoint="/metrics")

# Initialize pipeline components once at startup
normalizer = Normalizer()
enricher = Enricher()
cleaner = Cleaner()
db = DBWriter()

@app.get("/")
def health_check():
    """Health check endpoint."""
    return {
        "status": "running",
        "pipeline": "SOC AI Pipeline v1.0",
        "components": {
            "normalizer": "ready",
            "enricher": "ready",
            "cleaner": "ready",
            "database": "ready"
        }
    }

@app.post("/alert")
async def receive_alert(request: Request):
    """
    Main webhook endpoint.
    Wazuh sends alerts here via integration.
    Runs the full Layer 3 pipeline:
    normalize → enrich → clean → store
    """
    try:
        # Parse incoming JSON alert
        raw_alert = await request.json()
        ALERTS_RECEIVED.inc()
        logger.info(
            f"Received alert from "
            f"{raw_alert.get('agent', {}).get('name', 'unknown')} "
            f"rule {raw_alert.get('rule', {}).get('id', '?')}"
        )

        # Step 1 — Normalize
        normalized = normalizer.normalize(raw_alert)
        if not normalized:
            raise HTTPException(
                status_code=400,
                detail="Normalization failed"
            )

        # Step 2 — Enrich
        enriched = enricher.enrich(normalized)

        # Step 3 — Clean
        cleaned = cleaner.clean(enriched)

        # Step 4 — Store (only if not noise/duplicate)
        stored = False
        if cleaner.should_store(cleaned):
            stored = db.save_alert(cleaned)

        # Record the ingestion outcome for observability.
        if stored:
            ALERTS_STORED.inc()
        else:
            ALERTS_DROPPED.inc()

        return {
            "status": "processed",
            "alert_id": cleaned.get("alert_id"),
            "agent": cleaned.get("agent_name"),
            "rule_id": cleaned.get("rule_id"),
            "risk_score": cleaned.get("risk_score"),
            "is_noise": cleaned.get("is_noise"),
            "is_duplicate": cleaned.get("is_duplicate"),
            "stored": stored
        }

    except HTTPException:
        # Normalization 400s etc. count as failures but must propagate cleanly.
        ALERTS_FAILED.inc()
        raise
    except Exception as e:
        ALERTS_FAILED.inc()
        logger.error(f"Pipeline error: {e}")
        raise HTTPException(
            status_code=500,
            detail=str(e)
        )

@app.get("/stats")
def get_stats():
    """Return pipeline statistics."""
    try:
        recent = db.get_recent_alerts(minutes=60)
        return {
            "alerts_last_hour": len(recent),
            "sources": list(set(
                a["agent_name"] for a in recent
            ))
        }
    except Exception as e:
        return {"error": str(e)}

if __name__ == "__main__":
    uvicorn.run(
        "api.webhook:app",
        host=settings.PIPELINE_HOST,
        port=settings.PIPELINE_PORT,
        reload=False
    )
