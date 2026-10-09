"""
Endpoints de lecture des incidents et des KPIs.
Toutes les requêtes sont en LECTURE SEULE sur les tables du pipeline
(cases, enriched_alerts, feedback) — aucune modification.
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from typing import Optional
from database import query_all, query_one
from auth import get_current_user

router = APIRouter(prefix="/api", tags=["incidents"])


# ============================================================
#  LISTE DES INCIDENTS (dashboard)
# ============================================================
@router.get("/incidents")
def list_incidents(
    severity: Optional[str] = None,
    status: Optional[str] = None,
    tactic: Optional[str] = None,
    limit: int = Query(100, le=500),
    user: dict = Depends(get_current_user),
):
    """Retourne la liste des incidents (cases) avec filtres optionnels."""
    conditions = []
    params = []

    if severity:
        conditions.append("severity = %s")
        params.append(severity)
    if status:
        conditions.append("status = %s")
        params.append(status)
    if tactic:
        conditions.append("mitre_tactic = %s")
        params.append(tactic)

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    params.append(limit)

    sql = f"""
        SELECT case_id, title, severity, status,
               mitre_tactic, mitre_technique,
               affected_assets, alert_ids,
               fp_probability, remediation,
               created_at, updated_at
        FROM cases
        {where}
        ORDER BY created_at DESC
        LIMIT %s
    """
    return query_all(sql, tuple(params))


# ============================================================
#  DÉTAIL D'UN INCIDENT
# ============================================================
@router.get("/incidents/{case_id}")
def get_incident(case_id: str, user: dict = Depends(get_current_user)):
    """Retourne le détail d'un incident."""
    incident = query_one(
        """
        SELECT case_id, title, severity, status,
               mitre_tactic, mitre_technique,
               affected_assets, alert_ids,
               fp_probability, remediation,
               created_at, updated_at
        FROM cases WHERE case_id = %s
        """,
        (case_id,),
    )
    if not incident:
        raise HTTPException(status_code=404, detail="Incident introuvable")
    return incident


# ============================================================
#  ALERTES LIÉES À UN INCIDENT (pour le "Deep Analysis")
# ============================================================
@router.get("/incidents/{case_id}/alerts")
def get_incident_alerts(case_id: str, user: dict = Depends(get_current_user)):
    """
    Retourne les alertes enrichies composant l'incident.
    Utilise cases.alert_ids[] pour retrouver les détails dans enriched_alerts.
    C'est la source des informations "Incident Overview" et "AI Analysis".
    """
    case = query_one("SELECT alert_ids FROM cases WHERE case_id = %s", (case_id,))
    if not case:
        raise HTTPException(status_code=404, detail="Incident introuvable")

    alert_ids = case["alert_ids"] or []
    if not alert_ids:
        return []

    # Récupère toutes les alertes dont l'alert_id est dans la liste
    sql = """
        SELECT alert_id, timestamp, agent_name, agent_ip,
               rule_id, rule_description, rule_level,
               src_ip, dst_ip, src_port, dst_port, protocol,
               country, city, latitude, longitude,
               abuse_score, cvss_score, risk_score,
               mitre_tactic, mitre_technique,
               raw_alert, created_at
        FROM enriched_alerts
        WHERE alert_id = ANY(%s)
        ORDER BY timestamp ASC
    """
    return query_all(sql, (alert_ids,))


# ============================================================
#  KPIs (dashboard)
# ============================================================
@router.get("/kpis")
def get_kpis(user: dict = Depends(get_current_user)):
    """Retourne les indicateurs clés pour le tableau de bord."""

    # Totaux
    total_cases = query_one("SELECT COUNT(*) AS n FROM cases")["n"]
    total_alerts = query_one("SELECT COUNT(*) AS n FROM enriched_alerts")["n"]

    # Répartition par sévérité
    by_severity = query_all(
        "SELECT severity, COUNT(*) AS count FROM cases "
        "GROUP BY severity ORDER BY count DESC"
    )

    # Répartition par statut
    by_status = query_all(
        "SELECT status, COUNT(*) AS count FROM cases "
        "GROUP BY status ORDER BY count DESC"
    )

    # Répartition par tactique MITRE
    by_tactic = query_all(
        "SELECT mitre_tactic, COUNT(*) AS count FROM cases "
        "WHERE mitre_tactic IS NOT NULL "
        "GROUP BY mitre_tactic ORDER BY count DESC LIMIT 10"
    )

    # Taux vrais/faux positifs (depuis feedback)
    feedback_stats = query_all(
        "SELECT label, COUNT(*) AS count FROM feedback "
        "GROUP BY label"
    )

    # Score de risque moyen
    avg_risk = query_one(
        "SELECT ROUND(AVG(risk_score)::numeric, 1) AS avg FROM enriched_alerts "
        "WHERE risk_score IS NOT NULL"
    )["avg"]

    # Top IP sources
    top_sources = query_all(
        "SELECT src_ip, COUNT(*) AS count FROM enriched_alerts "
        "WHERE src_ip IS NOT NULL "
        "GROUP BY src_ip ORDER BY count DESC LIMIT 5"
    )

    # Incidents dans le temps (par jour, 7 derniers jours)
    timeline = query_all(
        "SELECT DATE(created_at) AS day, COUNT(*) AS count FROM cases "
        "WHERE created_at > NOW() - INTERVAL '7 days' "
        "GROUP BY DATE(created_at) ORDER BY day ASC"
    )

    # Incidents en attente d'approbation
    pending = query_one(
        "SELECT COUNT(*) AS n FROM cases WHERE status = 'pending_approval'"
    )["n"]

    return {
        "total_cases": total_cases,
        "total_alerts": total_alerts,
        "reduction_ratio": round(total_alerts / total_cases, 1) if total_cases else 0,
        "pending_approval": pending,
        "avg_risk_score": float(avg_risk) if avg_risk else 0,
        "by_severity": by_severity,
        "by_status": by_status,
        "by_tactic": by_tactic,
        "feedback_stats": feedback_stats,
        "top_sources": top_sources,
        "timeline": timeline,
    }
