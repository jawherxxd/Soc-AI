"""
Intégration iTop pour le backend UI.
Permet au bouton "Approve" de piloter iTop (Option 3) :
retrouve le ticket d'un cas et le résout avec le commentaire d'approbation,
reproduisant exactement le geste manuel de l'analyste.
La chaîne n8n existante (polling feedback + webhook containment) prend
ensuite le relais, sans modification.
"""
import json
import requests
from config import config


def _itop_call(operation_payload: dict) -> dict:
    """Appel générique à l'API REST d'iTop."""
    resp = requests.post(
        f"{config.ITOP_URL}?version={config.ITOP_VERSION}"
        if "?" not in config.ITOP_URL
        else f"{config.ITOP_URL}&version={config.ITOP_VERSION}",
        data={
            "auth_user": config.ITOP_USER,
            "auth_pwd": config.ITOP_PASSWORD,
            "json_data": json.dumps(operation_payload),
        },
        timeout=15,
    )
    resp.raise_for_status()
    return resp.json()


def find_ticket_by_case(case_id: str):
    """
    Retrouve le ticket Incident iTop correspondant à un cas.
    Le pipeline crée les tickets avec le titre '[CASE-XXXX] ...',
    on recherche donc par ce motif.
    Retourne l'id iTop du ticket, ou None si introuvable.
    """
    payload = {
        "operation": "core/get",
        "class": "Incident",
        "key": f"SELECT Incident WHERE title LIKE '%[{case_id}]%'",
        "output_fields": "id,friendlyname,status,title",
    }
    result = _itop_call(payload)
    if result.get("code") != 0:
        return None
    objects = result.get("objects") or {}
    for obj in objects.values():
        # Retourne le premier ticket trouvé
        return obj["key"]
    return None


def resolve_ticket_with_approval(case_id: str, src_ip: str) -> dict:
    """
    Résout le ticket iTop du cas avec le commentaire d'approbation,
    exactement comme le ferait l'analyste manuellement :
      statut -> resolved
      commentaire/solution -> 'TP - APPROVE BLOCK <src_ip>'
    C'est ce qui déclenche la chaîne n8n (feedback + containment).
    """
    ticket_id = find_ticket_by_case(case_id)
    if not ticket_id:
        raise ValueError(f"Ticket iTop introuvable pour le cas {case_id}")

    approval_comment = f"TP - APPROVE BLOCK {src_ip}"

    payload = {
        "operation": "core/update",
        "class": "Incident",
        "key": ticket_id,
        "comment": f"Approbation via plateforme SOC-AI — {case_id}",
        "fields": {
            "status": "resolved",
            "solution": approval_comment,
        },
        "output_fields": "id,friendlyname,status",
    }
    result = _itop_call(payload)
    if result.get("code") != 0:
        raise RuntimeError(f"Erreur iTop: {result.get('message')}")

    return {"ticket_id": ticket_id, "approval_comment": approval_comment}
