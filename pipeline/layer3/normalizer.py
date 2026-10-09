import hashlib
import json
from datetime import datetime
from loguru import logger


class Normalizer:
    """
    Maps raw Wazuh alert fields to
    Elastic Common Schema (ECS) format.
    Every source (FortiGate, Suricata,
    Windows, Linux) gets unified here.
    """

    def normalize(self, raw_alert: dict) -> dict:
        try:
            normalized = {
                # ── Identity ──────────────────
                "alert_id": self._generate_id(raw_alert),
                "timestamp": self._get_timestamp(raw_alert),

                # ── Agent info ────────────────
                "agent_name": raw_alert.get("agent", {}).get("name", "unknown"),
                "agent_ip": raw_alert.get("agent", {}).get("ip", "unknown"),

                # ── Rule info ─────────────────
                "rule_id": int(raw_alert.get("rule", {}).get("id", 0)),
                "rule_description": raw_alert.get("rule", {}).get("description", ""),
                "rule_level": int(raw_alert.get("rule", {}).get("level", 0)),
                "rule_groups": raw_alert.get("rule", {}).get("groups", []),

                # ── Network (ECS unified) ─────
                "src_ip": self._get_src_ip(raw_alert),
                "dst_ip": self._get_dst_ip(raw_alert),
                "src_port": self._get_src_port(raw_alert),
                "dst_port": self._get_dst_port(raw_alert),
                "protocol": self._get_protocol(raw_alert),

                # ── MITRE ATT&CK ──────────────
                "mitre_tactic": self._get_mitre_tactic(raw_alert),
                "mitre_technique": self._get_mitre_technique(raw_alert),

                # ── Source type ───────────────
                "source_type": self._detect_source(raw_alert),

                # ── Raw alert (keep original) ─
                "raw_alert": raw_alert,

                # ── Enrichment placeholders ───
                "abuse_score": None,
                "country": None,
                "city": None,
                "latitude": None,
                "longitude": None,
                "cvss_score": None,
                "risk_score": None,
                "is_duplicate": False,
                "is_noise": False,
            }

            logger.debug(
                f"Normalized alert {normalized['alert_id']} "
                f"from {normalized['agent_name']} "
                f"rule {normalized['rule_id']}"
            )
            return normalized

        except Exception as e:
            logger.error(f"Normalization error: {e}")
            return None

    def _generate_id(self, alert: dict) -> str:
        # Unique ID from timestamp + agent + rule
        raw = (
            f"{alert.get('timestamp', '')}"
            f"{alert.get('agent', {}).get('name', '')}"
            f"{alert.get('rule', {}).get('id', '')}"
            f"{alert.get('id', '')}"
        )
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def _get_timestamp(self, alert: dict) -> str:
        ts = alert.get("timestamp")
        if ts:
            return ts
        return datetime.utcnow().isoformat()

    def _get_src_ip(self, alert: dict) -> str:
        data = alert.get("data", {})
        # Try multiple field names from different sources
        for field in ["srcip", "src_ip", "source_ip",
                      "remote_ip", "data.src_ip"]:
            if data.get(field):
                return data[field]
        # Suricata EVE JSON
        if data.get("src_ip"):
            return data["src_ip"]
        # Windows Sysmon network event
        win = data.get("win", {}).get("eventdata", {})
        if win.get("sourceIp"):
            return win["sourceIp"]
        return None

    def _get_dst_ip(self, alert: dict) -> str:
        data = alert.get("data", {})
        for field in ["dstip", "dst_ip", "dest_ip",
                      "destination_ip"]:
            if data.get(field):
                return data[field]
        if data.get("dest_ip"):
            return data["dest_ip"]
        win = data.get("win", {}).get("eventdata", {})
        if win.get("destinationIp"):
            return win["destinationIp"]
        return None

    def _get_src_port(self, alert: dict) -> int:
        data = alert.get("data", {})
        for field in ["srcport", "src_port", "sport"]:
            val = data.get(field)
            if val:
                try:
                    return int(val)
                except:
                    pass
        win = data.get("win", {}).get("eventdata", {})
        if win.get("sourcePort"):
            try:
                return int(win["sourcePort"])
            except:
                pass
        return None

    def _get_dst_port(self, alert: dict) -> int:
        data = alert.get("data", {})
        for field in ["dstport", "dst_port", "dport", "dest_port"]:
            val = data.get(field)
            if val:
                try:
                    return int(val)
                except:
                    pass
        win = data.get("win", {}).get("eventdata", {})
        if win.get("destinationPort"):
            try:
                return int(win["destinationPort"])
            except:
                pass
        return None

    def _get_protocol(self, alert: dict) -> str:
        data = alert.get("data", {})
        for field in ["proto", "protocol", "transport"]:
            if data.get(field):
                return data[field].lower()
        return None

    def _get_mitre_tactic(self, alert: dict) -> str:
        mitre = alert.get("rule", {}).get("mitre", {})
        tactics = mitre.get("tactic", [])
        if tactics:
            return tactics[0] if isinstance(tactics, list) else tactics
        return None

    def _get_mitre_technique(self, alert: dict) -> str:
        mitre = alert.get("rule", {}).get("mitre", {})
        techniques = mitre.get("id", [])
        if techniques:
            return techniques[0] if isinstance(techniques, list) else techniques
        return None

    def _detect_source(self, alert: dict) -> str:
        agent = alert.get("agent", {}).get("name", "").lower()
        groups = alert.get("rule", {}).get("groups", [])
        groups_str = " ".join(groups).lower()

        if "fortigate" in groups_str or "fortigate" in agent:
            return "fortigate"
        elif "suricata" in groups_str or "suricata" in agent:
            return "suricata"
        elif "sysmon" in groups_str or "windows" in groups_str:
            return "windows"
        elif "linux" in agent or "ubuntu" in agent:
            return "linux"
        return "unknown"
