"""
Client n8n pour déclencher directement le playbook de containment (Option 1).
Reproduit exactement le body que le webhook attend :
  { "ref", "title", "solution": "TP -APPROVE BLOCK <ip>", "status": "resolved" }
Le workflow n8n lit l'IP à bloquer depuis le champ "solution".
"""
import requests
from config import config


def trigger_containment(case_id: str, title: str, src_ip: str, itop_ref: str = "") -> dict:
    """
    Appelle le webhook n8n containment pour bloquer une IP.
    Le champ 'solution' contient le mot-clé d'approbation avec l'IP,
    au format attendu par le workflow.
    """
    payload = {
        "ref": itop_ref or case_id,
        "title": f"[{case_id}] {title or ''}".strip(),
        "solution": f"<p>TP -APPROVE BLOCK {src_ip}</p>",
        "status": "resolved",
    }

    resp = requests.post(
        config.N8N_CONTAINMENT_URL,
        json=payload,
        timeout=15,
    )
    resp.raise_for_status()
    # n8n peut répondre avec ou sans corps JSON selon la config "Respond"
    try:
        return resp.json()
    except Exception:
        return {"ok": True, "status_code": resp.status_code}
