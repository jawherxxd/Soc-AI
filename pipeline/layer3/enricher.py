import requests
import geoip2.database
from loguru import logger
from config.settings import settings


class Enricher:
    """
    Adds threat intelligence context to
    each normalized alert using 3 sources:
    - AbuseIPDB  → IP reputation score
    - GeoIP      → geolocation data
    - NVD API    → CVE/CVSS details
    """

    def __init__(self):
        # Load GeoIP database once at startup
        try:
            self.geo_reader = geoip2.database.Reader(
                settings.GEOIP_DB
            )
            logger.info("GeoIP database loaded successfully")
        except Exception as e:
            logger.error(f"GeoIP load error: {e}")
            self.geo_reader = None

    def enrich(self, alert: dict) -> dict:
        """Run all enrichment on a normalized alert."""
        src_ip = alert.get("src_ip")

        # Only enrich if we have a source IP
        if src_ip and not self._is_private_ip(src_ip):
            alert = self._enrich_abuseipdb(alert, src_ip)
            alert = self._enrich_geoip(alert, src_ip)
        else:
            logger.debug(
                f"Skipping enrichment — "
                f"no public src_ip for alert {alert.get('alert_id')}"
            )

        # CVE enrichment from rule description
        alert = self._enrich_cve(alert)

        # Calculate risk score
        alert = self._calculate_risk_score(alert)

        return alert

    def _is_private_ip(self, ip: str) -> bool:
        """Skip enrichment for private/internal IPs."""
        private_ranges = [
            "10.", "192.168.", "172.16.", "172.17.",
            "172.18.", "172.19.", "172.20.", "172.21.",
            "172.22.", "172.23.", "172.24.", "172.25.",
            "172.26.", "172.27.", "172.28.", "172.29.",
            "172.30.", "172.31.", "127.", "0.0.0.0"
        ]
        return any(ip.startswith(r) for r in private_ranges)

    def _enrich_abuseipdb(self, alert: dict, ip: str) -> dict:
        """Get IP reputation score from AbuseIPDB."""
        try:
            response = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={
                    "Key": settings.ABUSEIPDB_KEY,
                    "Accept": "application/json"
                },
                params={
                    "ipAddress": ip,
                    "maxAgeInDays": 90
                },
                timeout=5
            )

            if response.status_code == 200:
                data = response.json().get("data", {})
                alert["abuse_score"] = data.get(
                    "abuseConfidenceScore", 0
                )
                logger.debug(
                    f"AbuseIPDB: {ip} → score {alert['abuse_score']}"
                )
            else:
                alert["abuse_score"] = 0
                logger.warning(
                    f"AbuseIPDB error {response.status_code} for {ip}"
                )

        except Exception as e:
            alert["abuse_score"] = 0
            logger.error(f"AbuseIPDB exception: {e}")

        return alert

    def _enrich_geoip(self, alert: dict, ip: str) -> dict:
        """Get geolocation from MaxMind GeoLite2."""
        if not self.geo_reader:
            return alert
        try:
            response = self.geo_reader.city(ip)
            alert["country"] = response.country.name
            alert["city"] = response.city.name
            alert["latitude"] = response.location.latitude
            alert["longitude"] = response.location.longitude
            logger.debug(
                f"GeoIP: {ip} → "
                f"{alert['country']}, {alert['city']}"
            )
        except Exception as e:
            logger.debug(f"GeoIP lookup failed for {ip}: {e}")

        return alert

    def _enrich_cve(self, alert: dict) -> dict:
        """Extract CVE from rule description and get CVSS score."""
        import re
        description = alert.get("rule_description", "")

        # Look for CVE pattern in rule description
        cve_match = re.search(r"CVE-\d{4}-\d+", description)
        if not cve_match:
            return alert

        cve_id = cve_match.group()
        try:
            headers = {}
            if settings.NVD_API_KEY:
                headers["apiKey"] = settings.NVD_API_KEY

            response = requests.get(
                settings.NVD_API_URL,
                headers=headers,
                params={"cveId": cve_id},
                timeout=10
            )

            if response.status_code == 200:
                data = response.json()
                vulns = data.get("vulnerabilities", [])
                if vulns:
                    metrics = vulns[0].get("cve", {}).get(
                        "metrics", {}
                    )
                    # Try CVSS v3 first then v2
                    cvss_data = (
                        metrics.get("cvssMetricV31", [{}])[0]
                        or metrics.get("cvssMetricV2", [{}])[0]
                    )
                    score = cvss_data.get(
                        "cvssData", {}
                    ).get("baseScore")
                    if score:
                        alert["cvss_score"] = float(score)
                        logger.debug(
                            f"NVD: {cve_id} → CVSS {score}"
                        )
        except Exception as e:
            logger.error(f"NVD API error for {cve_id}: {e}")

        return alert

    def _calculate_risk_score(self, alert: dict) -> float:
        """
        Calculate a composite risk score 0-100
        based on available enrichment data.

        Formula:
          40% rule severity (Wazuh level 0-15)
          30% IP abuse score (AbuseIPDB 0-100)
          30% CVSS score (NVD 0-10)
        """
        # Normalize each component to 0-100
        severity_score = (
            (alert.get("rule_level", 0) / 15) * 100
        )
        abuse_score = alert.get("abuse_score") or 0
        cvss_raw = alert.get("cvss_score") or 0
        cvss_score = (cvss_raw / 10) * 100

        # Weighted formula
        risk = (
            (severity_score * 0.4) +
            (abuse_score * 0.3) +
            (cvss_score * 0.3)
        )

        alert["risk_score"] = round(risk, 2)
        logger.debug(
            f"Risk score: {alert['risk_score']} "
            f"(severity={severity_score:.0f}, "
            f"abuse={abuse_score}, cvss={cvss_score:.0f})"
        )
        return alert
