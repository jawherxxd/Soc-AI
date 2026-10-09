import uuid
import json
import requests
import psycopg2
from loguru import logger
from config.settings import settings


class CaseCreator:
    """
    Creates structured incident cases in PostgreSQL
    and sends them to iTop with:
    - Proper caller + agent assignment
    - Correct impact/urgency/priority mapping
    - Professional HTML description
    - Human-in-the-Loop SOAR instructions
    """

    # Severity → impact + urgency + priority mapping
    SEVERITY_MAP = {
        "critical": {"impact": "1", "urgency": "1", "priority": "1"},
        "high":     {"impact": "2", "urgency": "1", "priority": "2"},
        "medium":   {"impact": "2", "urgency": "2", "priority": "3"},
        "low":      {"impact": "3", "urgency": "3", "priority": "4"},
    }

    SEVERITY_COLOR = {
        "critical": "#cc0000",
        "high":     "#ff6600",
        "medium":   "#ff9900",
        "low":      "#009900",
    }

    def __init__(self):
        self.conn = None
        self._connect()

    def _connect(self):
        try:
            self.conn = psycopg2.connect(
                host=settings.DB_HOST,
                port=settings.DB_PORT,
                dbname=settings.DB_NAME,
                user=settings.DB_USER,
                password=settings.DB_PASSWORD
            )
            self.conn.autocommit = True
            logger.info("CaseCreator DB connected")
        except Exception as e:
            logger.error(f"CaseCreator DB error: {e}")

    def create_case(
        self,
        llm_result: dict,
        alert_group: list
    ) -> str:
        """
        Main method — creates case and sends to iTop.
        Returns case_id if TP, None if FP.
        """
        if not llm_result.get("is_true_positive"):
            logger.info(
                f"FP skipped: {llm_result.get('case_title')}"
            )
            return None

        case_id = f"CASE-{uuid.uuid4().hex[:8].upper()}"
        alert_ids = [a.get("alert_id") for a in alert_group]
        affected_assets = llm_result.get("affected_assets", [])
        severity = llm_result.get("severity", "medium")
        proposed_actions = self._build_proposed_actions(
            llm_result, alert_group, severity
        )

        saved = self._save_to_db(
            case_id, llm_result,
            alert_ids, affected_assets
        )
        if not saved:
            return None

        self._send_to_itop(
            case_id, llm_result,
            alert_group, proposed_actions
        )
        return case_id

    def _build_proposed_actions(
        self,
        llm_result: dict,
        alert_group: list,
        severity: str
    ) -> list:
        """Build proposed SOAR actions by severity."""
        actions = []
        src_ips = list(set(
            a.get("src_ip") for a in alert_group
            if a.get("src_ip")
        ))
        dst_ips = list(set(
            a.get("dst_ip") for a in alert_group
            if a.get("dst_ip")
        ))

        if severity in ["high", "critical"]:
            for ip in src_ips:
                if ip and not ip.startswith("10."):
                    actions.append({
                        "action": "block_ip_fortigate",
                        "target": ip,
                        "description": f"Block {ip} on FortiGate firewall",
                        "risk": "low",
                        "requires_approval": True
                    })
            for ip in dst_ips:
                if ip and ip.startswith("10."):
                    actions.append({
                        "action": "isolate_host",
                        "target": ip,
                        "description": f"Isolate host {ip} from network",
                        "risk": "high",
                        "requires_approval": True
                    })

        for ip in src_ips:
            if ip:
                actions.append({
                    "action": "add_to_watchlist",
                    "target": ip,
                    "description": f"Add {ip} to monitoring watchlist",
                    "risk": "none",
                    "requires_approval": False
                })

        actions.append({
            "action": "notify_analyst",
            "target": "slack",
            "description": "Send Slack alert to SOC team",
            "risk": "none",
            "requires_approval": False
        })
        return actions

    def _save_to_db(
        self,
        case_id: str,
        llm_result: dict,
        alert_ids: list,
        affected_assets: list
    ) -> bool:
        """Save case to PostgreSQL."""
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                INSERT INTO cases (
                    case_id, title, severity, status,
                    mitre_tactic, mitre_technique,
                    affected_assets, alert_ids,
                    fp_probability, remediation,
                    created_at, updated_at
                ) VALUES (
                    %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,
                    NOW(),NOW()
                ) ON CONFLICT (case_id) DO NOTHING
            """, (
                case_id,
                llm_result.get("case_title"),
                llm_result.get("severity"),
                "pending_approval",
                llm_result.get("mitre_tactic"),
                llm_result.get("mitre_technique"),
                affected_assets,
                alert_ids,
                (0.05 if llm_result.get("is_true_positive") else 0.90),
                "\n".join(llm_result.get("remediation_steps", []))
            ))
            logger.info(
                f"Case saved: {case_id} | "
                f"{llm_result.get('severity')} | "
                f"{llm_result.get('case_title')}"
            )
            return True
        except Exception as e:
            logger.error(f"DB save error: {e}")
            return False

    def _build_html_description(
        self,
        case_id: str,
        llm_result: dict,
        alert_group: list,
        proposed_actions: list
    ) -> str:
        """Build professional HTML description for iTop."""
        severity = llm_result.get("severity", "medium")
        color = self.SEVERITY_COLOR.get(severity, "#333")

        # Remediation steps
        remediation_rows = "".join([
            f"<tr><td style='padding:6px;border:1px solid #ddd'>"
            f"{i+1}</td>"
            f"<td style='padding:6px;border:1px solid #ddd'>"
            f"{step}</td></tr>"
            for i, step in enumerate(
                llm_result.get("remediation_steps", [])
            )
        ])

        # Proposed actions
        action_rows = "".join([
            f"<tr>"
            f"<td style='padding:6px;border:1px solid #ddd'>"
            f"{a['description']}</td>"
            f"<td style='padding:6px;border:1px solid #ddd;"
            f"color:{'#cc0000' if a['risk']=='high' else '#333'}'>"
            f"{a['risk'].upper()}</td>"
            f"<td style='padding:6px;border:1px solid #ddd'>"
            f"{'⚠️ APPROVAL NEEDED' if a['requires_approval'] else '✅ AUTO'}"
            f"</td></tr>"
            for a in proposed_actions
        ])

        assets = ", ".join(
            llm_result.get("affected_assets", [])
        ) or "N/A"

        return f"""
<div style="font-family:Arial,sans-serif;max-width:900px">

<div style="background:{color};color:white;padding:12px 16px;
border-radius:6px;margin-bottom:16px">
<h2 style="margin:0;font-size:18px">
🚨 {llm_result.get('case_title')}
</h2>
<span style="font-size:13px;opacity:0.9">
Case ID: {case_id} &nbsp;|&nbsp;
Severity: {severity.upper()} &nbsp;|&nbsp;
Generated by SOC AI Pipeline
</span>
</div>

<table style="width:100%;border-collapse:collapse;
margin-bottom:16px;font-size:13px">
<tr style="background:#f5f5f5">
<th style="padding:8px;border:1px solid #ddd;
text-align:left;width:30%">Field</th>
<th style="padding:8px;border:1px solid #ddd;
text-align:left">Value</th>
</tr>
<tr><td style="padding:8px;border:1px solid #ddd">
<b>Attack pattern</b></td>
<td style="padding:8px;border:1px solid #ddd">
{llm_result.get('attack_pattern')}</td></tr>
<tr style="background:#fafafa">
<td style="padding:8px;border:1px solid #ddd">
<b>MITRE tactic</b></td>
<td style="padding:8px;border:1px solid #ddd">
{llm_result.get('mitre_tactic')}</td></tr>
<tr><td style="padding:8px;border:1px solid #ddd">
<b>MITRE technique</b></td>
<td style="padding:8px;border:1px solid #ddd">
{llm_result.get('mitre_technique')}</td></tr>
<tr style="background:#fafafa">
<td style="padding:8px;border:1px solid #ddd">
<b>Affected assets</b></td>
<td style="padding:8px;border:1px solid #ddd">
{assets}</td></tr>
<tr><td style="padding:8px;border:1px solid #ddd">
<b>Alerts grouped</b></td>
<td style="padding:8px;border:1px solid #ddd">
{len(alert_group)} alerts</td></tr>
</table>

<h3 style="color:#333;border-bottom:2px solid {color};
padding-bottom:6px">📋 AI Remediation Steps</h3>
<table style="width:100%;border-collapse:collapse;
font-size:13px;margin-bottom:16px">
<tr style="background:#f5f5f5">
<th style="padding:8px;border:1px solid #ddd;width:40px">#</th>
<th style="padding:8px;border:1px solid #ddd">Action</th>
</tr>
{remediation_rows}
</table>

<h3 style="color:#333;border-bottom:2px solid {color};
padding-bottom:6px">⚡ Proposed SOAR Actions</h3>
<table style="width:100%;border-collapse:collapse;
font-size:13px;margin-bottom:16px">
<tr style="background:#f5f5f5">
<th style="padding:8px;border:1px solid #ddd">Action</th>
<th style="padding:8px;border:1px solid #ddd;width:80px">Risk</th>
<th style="padding:8px;border:1px solid #ddd;width:160px">Status</th>
</tr>
{action_rows}
</table>

<div style="background:#fff3cd;border:1px solid #ffc107;
border-radius:6px;padding:12px;font-size:13px">
<b>📌 Instructions for Analyst (jawher yahyaoui)</b><br><br>
1. Review the proposed SOAR actions above carefully.<br>
2. <b>Approve</b> actions you want n8n to execute.<br>
3. <b>Reject</b> any actions that are incorrect.<br>
4. Actions marked ✅ AUTO will execute immediately.<br>
5. After review — close this ticket and label as
<b>True Positive</b> or <b>False Positive</b>.<br>
6. Your feedback trains the AI for future incidents.
</div>

</div>
"""

    def _send_to_itop(
        self,
        case_id: str,
        llm_result: dict,
        alert_group: list,
        proposed_actions: list
    ) -> None:
        """Send case to iTop with full analyst assignment."""
        if not (hasattr(settings, 'ITOP_URL') and settings.ITOP_URL):
            logger.info(f"iTop not configured — {case_id} DB only")
            return

        severity = llm_result.get("severity", "medium")
        sev_map = self.SEVERITY_MAP.get(
            severity, self.SEVERITY_MAP["medium"]
        )

        description = self._build_html_description(
            case_id, llm_result, alert_group, proposed_actions
        )

        itop_payload = {
            "operation": "core/create",
            "class": "Incident",
            "comment": f"Auto-created by SOC AI Pipeline — {case_id}",
            "fields": {
                "title": (
                    f"[{case_id}] "
                    f"{llm_result.get('case_title')}"
                ),
                "description": description,
                "org_id": (
                    f"SELECT Organization "
                    f"WHERE name = \"{settings.ITOP_ORG}\""
                ),
                # Caller = jawher yahyaoui (ID:3)
                "caller_id": (
                    f"SELECT Person WHERE "
                    f"name = \"{settings.ITOP_ANALYST_NAME}\" "
                    f"AND first_name = \"{settings.ITOP_ANALYST_FIRSTNAME}\""
                ),
                # Agent = jawher yahyaoui
                "agent_id": (
                    f"SELECT Person WHERE "
                    f"name = \"{settings.ITOP_ANALYST_NAME}\" "
                    f"AND first_name = \"{settings.ITOP_ANALYST_FIRSTNAME}\""
                ),
                # Team = SOC Tier 1
                "team_id": (
                    f"SELECT Team WHERE "
                    f"name = \"{settings.ITOP_TEAM_NAME}\""
                ),
                "impact":   sev_map["impact"],
                "urgency":  sev_map["urgency"],
                "priority": sev_map["priority"],
                "origin":   "monitoring",
                "status":   "assigned"
            },
            "output_fields": "id,friendlyname,status"
        }

        try:
            response = requests.post(
                f"{settings.ITOP_URL}/webservices/rest.php?version=1.3",
                data={
                    "auth_user": settings.ITOP_USER,
                    "auth_pwd":  settings.ITOP_PASSWORD,
                    "json_data": json.dumps(itop_payload)
                },
                timeout=10
            )
            result = response.json()
            if result.get("code") == 0:
                for obj in result.get("objects", {}).values():
                    ticket_name = obj["fields"].get("friendlyname")
                    ticket_status = obj["fields"].get("status")
                    logger.info(
                        f"iTop ticket created: {ticket_name} "
                        f"status={ticket_status} "
                        f"assigned=jawher yahyaoui "
                        f"for case {case_id}"
                    )
            else:
                logger.warning(
                    f"iTop error code {result.get('code')}: "
                    f"{result.get('message')}"
                )
        except Exception as e:
            logger.warning(f"iTop send error: {e}")

    def get_open_cases(self) -> list:
        """Fetch all open/pending cases."""
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT
                    case_id, title, severity, status,
                    mitre_tactic, affected_assets,
                    remediation, created_at
                FROM cases
                WHERE status IN ('open','pending_approval')
                ORDER BY
                    CASE severity
                        WHEN 'critical' THEN 1
                        WHEN 'high'     THEN 2
                        WHEN 'medium'   THEN 3
                        WHEN 'low'      THEN 4
                    END,
                    created_at DESC
            """)
            columns = [d[0] for d in cursor.description]
            return [
                dict(zip(columns, row))
                for row in cursor.fetchall()
            ]
        except Exception as e:
            logger.error(f"Get cases error: {e}")
            return []

    def close_case(
        self,
        case_id: str,
        label: str,
        analyst: str = "jawher yahyaoui"
    ) -> bool:
        """Close case with TP/FP label."""
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                UPDATE cases
                SET status='closed', updated_at=NOW()
                WHERE case_id=%s
            """, (case_id,))
            cursor.execute("""
                INSERT INTO feedback
                (case_id, label, analyst, created_at)
                VALUES (%s,%s,%s,NOW())
            """, (case_id, label, analyst))
            logger.info(
                f"Case {case_id} closed — "
                f"{label} by {analyst}"
            )
            return True
        except Exception as e:
            logger.error(f"Close case error: {e}")
            return False
