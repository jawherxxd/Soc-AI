import psycopg2
from psycopg2.extras import RealDictCursor
from datetime import datetime
from loguru import logger
from config.settings import settings


class Correlator:
    """
    Reads unprocessed enriched alerts from
    PostgreSQL and groups them into incident
    clusters using rule-based logic.

    Grouping rules:
    1. Same src_ip within time window
    2. Same MITRE tactic within time window
    3. Same agent within time window

    Minimum 2 alerts to form a group.
    Single alerts are processed individually.
    """

    def __init__(self):
        self.conn = None
        self._connect()
        self.window = settings.CORRELATION_WINDOW_SECONDS

    def _connect(self):
        try:
            self.conn = psycopg2.connect(
                host=settings.DB_HOST,
                port=settings.DB_PORT,
                dbname=settings.DB_NAME,
                user=settings.DB_USER,
                password=settings.DB_PASSWORD,
                cursor_factory=RealDictCursor
            )
            self.conn.autocommit = True
            logger.info("Correlator DB connected")
        except Exception as e:
            logger.error(f"Correlator DB error: {e}")

    def fetch_unprocessed(self) -> list:
        """
        Fetch unprocessed alerts from
        last 5 minutes only.
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT
                    alert_id, timestamp, agent_name,
                    agent_ip, src_ip, dst_ip,
                    rule_id, rule_description, rule_level,
                    mitre_tactic, mitre_technique,
                    abuse_score, country, city,
                    risk_score, dst_port, protocol
                FROM enriched_alerts
                WHERE
                    is_processed = FALSE
                    AND is_noise = FALSE
                    AND is_duplicate = FALSE
                    AND created_at >= NOW() - INTERVAL '%s seconds'
                ORDER BY created_at ASC
            """, (self.window,))

            alerts = [dict(row) for row in cursor.fetchall()]
            logger.info(
                f"Fetched {len(alerts)} unprocessed alerts "
                f"from last {self.window}s"
            )
            return alerts

        except Exception as e:
            logger.error(f"Fetch error: {e}")
            return []

    def correlate(self, alerts: list) -> list:
        """
        Group alerts into incident clusters.
        Returns list of groups — each group
        is a list of related alerts.
        """
        if not alerts:
            return []

        groups = {}

        for alert in alerts:
            key = self._get_group_key(alert)
            if key not in groups:
                groups[key] = []
            groups[key].append(alert)

        # Convert to list of groups
        incident_groups = list(groups.values())

        logger.info(
            f"Correlated {len(alerts)} alerts "
            f"into {len(incident_groups)} groups"
        )

        # Log each group summary
        for i, group in enumerate(incident_groups):
            src_ips = set(
                a["src_ip"] for a in group if a.get("src_ip")
            )
            tactics = set(
                a["mitre_tactic"]
                for a in group if a.get("mitre_tactic")
            )
            logger.debug(
                f"Group {i+1}: {len(group)} alerts | "
                f"src_ips: {src_ips} | "
                f"tactics: {tactics}"
            )

        return incident_groups

    def _get_group_key(self, alert: dict) -> str:
        """
        Build grouping key for an alert.
        Priority:
        1. Same src_ip → strongest signal
        2. Same MITRE tactic → attack pattern
        3. Same agent → fallback grouping
        """
        src_ip = alert.get("src_ip") or "no_ip"
        tactic = alert.get("mitre_tactic") or "no_tactic"
        agent = alert.get("agent_name") or "unknown"

        # Group by src_ip + tactic (most meaningful)
        if src_ip != "no_ip":
            return f"{src_ip}:{tactic}"

        # Fallback: group by agent + tactic
        return f"{agent}:{tactic}"

    def mark_as_processed(self, alert_ids: list) -> None:
        """
        Mark alerts as processed so Layer 4
        never reads them again.
        """
        if not alert_ids:
            return
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                UPDATE enriched_alerts
                SET is_processed = TRUE
                WHERE alert_id = ANY(%s)
            """, (alert_ids,))

            logger.info(
                f"Marked {len(alert_ids)} alerts as processed"
            )
        except Exception as e:
            logger.error(f"Mark processed error: {e}")
