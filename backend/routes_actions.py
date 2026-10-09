"""
Endpoints d'action : approbation du blocage et feedback.
- /approve : pilote iTop (Option 3) pour déclencher la chaîne n8n existante
- /feedback : enregistre un verdict (utilisé par le bouton Reject FP)
"""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Literal
from database import query_one, query_all, execute
from auth import get_current_user
import n8n_client

router = APIRouter(prefix="/api/incidents", tags=["actions"])


class FeedbackBody(BaseModel):
    label: Literal["true_positive", "false_positive"]


def _get_case_src_ip(case_id: str):
    """Récupère l'IP source à bloquer depuis les alertes du cas."""
    case = query_one("SELECT case_id, title, alert_ids FROM cases WHERE case_id = %s", (case_id,))
    if not case:
        return None, None
    alert_ids = case["alert_ids"] or []
    if not alert_ids:
        return case, None
    # Prend l'IP source la plus fréquente parmi les alertes du cas
    row = query_one(
        """
        SELECT src_ip, COUNT(*) AS n
        FROM enriched_alerts
        WHERE alert_id = ANY(%s) AND src_ip IS NOT NULL
        GROUP BY src_ip ORDER BY n DESC LIMIT 1
        """,
        (alert_ids,),
    )
    return case, (row["src_ip"] if row else None)


# ============================================================
#  APPROBATION DU BLOCAGE (Option 1 — déclenche n8n directement)
# ============================================================
@router.post("/{case_id}/approve")
def approve_block(case_id: str, user: dict = Depends(get_current_user)):
    """
    Approuve le blocage : déclenche directement le playbook n8n containment
    avec l'IP source à bloquer. La plateforme est le point de contrôle ;
    iTop reste un simple registre d'incidents (ITSM).
    """
    case, src_ip = _get_case_src_ip(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Incident introuvable")
    if not src_ip:
        raise HTTPException(status_code=400, detail="Aucune IP source à bloquer pour cet incident")

    try:
        n8n_client.trigger_containment(
            case_id=case_id,
            title=case.get("title", ""),
            src_ip=src_ip,
        )
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Erreur n8n: {e}")

    # Enregistre le verdict TP (l'approbation implique un vrai positif)
    existing = query_one("SELECT id FROM feedback WHERE case_id = %s", (case_id,))
    if not existing:
        alert_ids = case.get("alert_ids") or []
        first_alert = alert_ids[0] if alert_ids else None
        execute(
            "INSERT INTO feedback (case_id, alert_id, label, analyst) VALUES (%s, %s, %s, %s)",
            (case_id, first_alert, "true_positive", user["username"]),
        )

    # Met à jour le statut du cas
    execute(
        "UPDATE cases SET status = 'resolved', updated_at = now() WHERE case_id = %s",
        (case_id,),
    )

    return {
        "status": "approved",
        "blocked_ip": src_ip,
        "message": f"Blocage de {src_ip} déclenché via n8n",
        "analyst": user["username"],
    }


# ============================================================
#  FEEDBACK (utilisé par le bouton Reject FP)
# ============================================================
@router.post("/{case_id}/feedback")
def submit_feedback(case_id: str, body: FeedbackBody, user: dict = Depends(get_current_user)):
    """
    Enregistre un verdict d'analyste (true_positive / false_positive).
    Idempotent : un seul verdict par cas.
    Écrit dans la même table feedback que la chaîne n8n, avec la même structure.
    """
    case = query_one("SELECT case_id, alert_ids FROM cases WHERE case_id = %s", (case_id,))
    if not case:
        raise HTTPException(status_code=404, detail="Incident introuvable")

    # Idempotence : ne pas dupliquer un verdict existant
    existing = query_one("SELECT id FROM feedback WHERE case_id = %s", (case_id,))
    if existing:
        return {"status": "already_recorded", "case_id": case_id}

    alert_ids = case["alert_ids"] or []
    first_alert = alert_ids[0] if alert_ids else None

    status_map = {"true_positive": "closed_tp", "false_positive": "closed_fp"}

    # Enregistre le feedback
    execute(
        "INSERT INTO feedback (case_id, alert_id, label, analyst) VALUES (%s, %s, %s, %s)",
        (case_id, first_alert, body.label, user["username"]),
    )
    # Met à jour le statut du cas
    execute(
        "UPDATE cases SET status = %s, updated_at = now() WHERE case_id = %s",
        (status_map[body.label], case_id),
    )

    return {
        "status": "recorded",
        "case_id": case_id,
        "label": body.label,
        "analyst": user["username"],
    }
