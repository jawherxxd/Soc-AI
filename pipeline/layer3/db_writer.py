import json
import psycopg2
from psycopg2.extras import Json
from loguru import logger
from config.settings import settings


class DBWriter:
    """
    Saves enriched alerts to PostgreSQL.
    Handles connection, insertion, and errors.
    """

    def __init__(self):
        self.conn = None
        self._connect()

    def _connect(self):
        """Establish PostgreSQL connection."""
        try:
            self.conn = psycopg2.connect(
                host=settings.DB_HOST,
                port=settings.DB_PORT,
                dbname=settings.DB_NAME,
                user=settings.DB_USER,
                password=settings.DB_PASSWORD
            )
            self.conn.autocommit = True
            logger.info("PostgreSQL connected successfully")
        except Exception as e:
            logger.error(f"PostgreSQL connection error: {e}")
            self.conn = None

    def _ensure_connection(self):
        """Reconnect if connection was lost."""
        try:
            if self.conn is None or self.conn.closed:
                self._connect()
            else:
                self.conn.cursor().execute("SELECT 1")
        except Exception:
            self._connect()

    def save_alert(self, alert: dict) -> bool:
        """
        Insert enriched alert into PostgreSQL.
        Returns True if saved, False if failed.
        """
        self._ensure_connection()
        if not self.conn:
            logger.error("No DB connection — alert not saved")
            return False

        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                INSERT INTO enriched_alerts (
                    alert_id, timestamp, agent_name, agent_ip,
                    rule_id, rule_description, rule_level,
                    src_ip, dst_ip, src_port, dst_port, protocol,
                    country, city, latitude, longitude,
                    abuse_score, cvss_score, risk_score,
                    mitre_tactic, mitre_technique,
                    is_duplicate, is_noise, raw_alert
                ) VALUES (
                    %s, %s, %s, %s,
                    %s, %s, %s,
                    %s, %s, %s, %s, %s,
                    %s, %s, %s, %s,
                    %s, %s, %s,
                    %s, %s,
                    %s, %s, %s
                )
                ON CONFLICT (alert_id) DO NOTHING
            """, (
                alert.get("alert_id"),
                alert.get("timestamp"),
                alert.get("agent_name"),
                alert.get("agent_ip"),
                alert.get("rule_id"),
                alert.get("rule_description"),
                alert.get("rule_level"),
                alert.get("src_ip"),
                alert.get("dst_ip"),
                alert.get("src_port"),
                alert.get("dst_port"),
                alert.get("protocol"),
                alert.get("country"),
                alert.get("city"),
                alert.get("latitude"),
                alert.get("longitude"),
                alert.get("abuse_score"),
                alert.get("cvss_score"),
                alert.get("risk_score"),
                alert.get("mitre_tactic"),
                alert.get("mitre_technique"),
                alert.get("is_duplicate", False),
                alert.get("is_noise", False),
                Json(alert.get("raw_alert", {}))
            ))

            logger.info(
                f"Saved alert {alert.get('alert_id')} "
                f"from {alert.get('agent_name')} "
                f"rule {alert.get('rule_id')} "
                f"risk {alert.get('risk_score')}"
            )
            return True

        except Exception as e:
            logger.error(f"DB insert error: {e}")
            return False

    def get_recent_alerts(self, minutes: int = 5) -> list:
        """
        Fetch alerts from last N minutes.
        Used by Layer 4 correlator.
        """
        self._ensure_connection()
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT
                    alert_id, timestamp, agent_name,
                    src_ip, dst_ip, rule_id,
                    rule_description, rule_level,
                    mitre_tactic, mitre_technique,
                    abuse_score, country, risk_score
                FROM enriched_alerts
                WHERE
                    created_at >= NOW() - INTERVAL '%s minutes'
                    AND is_noise = FALSE
                    AND is_duplicate = FALSE
                ORDER BY timestamp DESC
            """, (minutes,))

            rows = cursor.fetchall()
            columns = [desc[0] for desc in cursor.description]
            return [dict(zip(columns, row)) for row in rows]

        except Exception as e:
            logger.error(f"DB fetch error: {e}")
            return []

    def close(self):
        if self.conn:
            self.conn.close()
            logger.info("PostgreSQL connection closed")
