import sys
import os
sys.path.insert(0, '/home/jawher/soc-pipeline')

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional, Literal
from loguru import logger
import psycopg2
import psycopg2.extras

from config.settings import settings

router = APIRouter()


# --- Request body schema ----------------------------------------------------
# n8n will POST JSON matching this shape. Pydantic validates it for us, so a
# malformed payload returns a clean 422 instead of crashing the handler.
class FeedbackIn(BaseModel):
    case_id: str
    label: Literal["true_positive", "false_positive"]
    analyst: Optional[str] = "unknown"


# Map the incoming label to the resulting case status.
LABEL_TO_STATUS = {
    "true_positive": "closed_tp",
    "false_positive": "closed_fp",
}


def _get_connection():
    """Open a short-lived PostgreSQL connection from settings.

    One connection per request, closed in a finally block. This deliberately
    avoids a long-lived idle handle (the stale-connection problem that blinded
    the engine earlier).
    """
    return psycopg2.connect(
        host=settings.DB_HOST,
        port=settings.DB_PORT,
        dbname=settings.DB_NAME,
        user=settings.DB_USER,
        password=settings.DB_PASSWORD,
    )


@router.post("/feedback")
def receive_feedback(payload: FeedbackIn):
    """Receive an analyst verdict for a case and record it.

    This endpoint is IDEMPOTENT: if a verdict for the same case has already
    been recorded, repeated calls are ignored (returned as 'already_recorded'
    with a 200). This makes it safe for the n8n scheduler to re-poll the same
    resolved iTop ticket every minute, and safe under retry-on-fail, without
    writing duplicate feedback rows or re-closing the case. Rule: one verdict
    per case, first one wins.
    """
    conn = None
    try:
        conn = _get_connection()
        # RealDictCursor lets us read columns by name instead of by index.
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

        # 1) Find the case and its alert_ids.
        cur.execute(
            "SELECT case_id, alert_ids, status FROM cases WHERE case_id = %s;",
            (payload.case_id,),
        )
        case = cur.fetchone()

        if not case:
            # Unknown case_id: tell the caller clearly (404) rather than
            # silently doing nothing.
            raise HTTPException(
                status_code=404,
                detail=f"Case {payload.case_id} not found",
            )

        # 1b) IDEMPOTENCY GUARD.
        #     If feedback already exists for this case, do nothing and report
        #     it as already recorded. We return 200 (not an error) on purpose
        #     so n8n's scheduler/retry sees success and the workflow stays
        #     green instead of lighting up red every cycle.
        cur.execute(
            "SELECT 1 FROM feedback WHERE case_id = %s LIMIT 1;",
            (payload.case_id,),
        )
        if cur.fetchone():
            logger.info(
                f"Feedback for {payload.case_id} already recorded - "
                f"ignoring duplicate from {payload.analyst}."
            )
            return {
                "status": "already_recorded",
                "case_id": payload.case_id,
                "detail": "A verdict for this case was already saved; "
                          "duplicate ignored.",
            }

        # alert_ids is a Postgres text[] -> comes back as a Python list.
        alert_ids = case.get("alert_ids") or []

        # 2) Write one feedback row per alert in the case.
        #    If the case somehow has no alert_ids, still record one row with a
        #    NULL alert_id so the verdict isn't lost.
        if alert_ids:
            rows = [
                (payload.case_id, alert_id, payload.label, payload.analyst)
                for alert_id in alert_ids
            ]
            psycopg2.extras.execute_values(
                cur,
                "INSERT INTO feedback (case_id, alert_id, label, analyst) "
                "VALUES %s;",
                rows,
            )
        else:
            cur.execute(
                "INSERT INTO feedback (case_id, alert_id, label, analyst) "
                "VALUES (%s, %s, %s, %s);",
                (payload.case_id, None, payload.label, payload.analyst),
            )

        # 3) Update the case status + bump updated_at.
        new_status = LABEL_TO_STATUS[payload.label]
        cur.execute(
            "UPDATE cases SET status = %s, updated_at = now() "
            "WHERE case_id = %s;",
            (new_status, payload.case_id),
        )

        conn.commit()

        logger.success(
            f"Feedback recorded for {payload.case_id}: {payload.label} "
            f"by {payload.analyst} -> status={new_status}, "
            f"{len(alert_ids)} alert row(s)."
        )

        return {
            "status": "recorded",
            "case_id": payload.case_id,
            "label": payload.label,
            "new_status": new_status,
            "feedback_rows": len(alert_ids) if alert_ids else 1,
        }

    except HTTPException:
        # Already a clean HTTP error (e.g. 404) - let it through unchanged.
        raise
    except Exception as e:
        if conn:
            conn.rollback()
        logger.error(f"Feedback error for {payload.case_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if conn:
            conn.close()
