import hashlib
import redis
from loguru import logger
from config.settings import settings


class Cleaner:
    """
    Removes noise and duplicates before
    storing alerts in PostgreSQL.

    Two operations:
    1. Deduplication  → Redis TTL fingerprint
    2. Noise filter   → rule ID blocklist
    """

    def __init__(self):
        self.redis = redis.Redis(
            host=settings.REDIS_HOST,
            port=settings.REDIS_PORT,
            decode_responses=True
        )
        self.noise_rules = set(settings.NOISE_RULE_IDS)
        self.ttl = settings.DEDUP_WINDOW_SECONDS
        logger.info(
            f"Cleaner ready — "
            f"noise rules: {self.noise_rules}, "
            f"dedup window: {self.ttl}s"
        )

    def clean(self, alert: dict) -> dict:
        """
        Returns alert with is_duplicate and
        is_noise flags set. Caller decides
        whether to store or discard.
        """
        alert = self._check_noise(alert)
        alert = self._check_duplicate(alert)
        return alert

    def _check_noise(self, alert: dict) -> dict:
        """Flag low-signal rule IDs as noise."""
        rule_id = alert.get("rule_id", 0)
        if rule_id in self.noise_rules:
            alert["is_noise"] = True
            logger.debug(
                f"Noise: rule {rule_id} is in blocklist"
            )
        else:
            alert["is_noise"] = False
        return alert

    def _check_duplicate(self, alert: dict) -> dict:
        """
        Fingerprint = hash of src_ip + rule_id + dst_port.
        If same fingerprint seen within TTL window → duplicate.
        """
        src_ip = alert.get("src_ip") or "none"
        rule_id = str(alert.get("rule_id") or "0")
        dst_port = str(alert.get("dst_port") or "0")
        agent = alert.get("agent_name") or "unknown"

        raw = f"{src_ip}:{rule_id}:{dst_port}:{agent}"
        fingerprint = hashlib.md5(raw.encode()).hexdigest()
        redis_key = f"dedup:{fingerprint}"

        try:
            exists = self.redis.get(redis_key)
            if exists:
                alert["is_duplicate"] = True
                logger.debug(
                    f"Duplicate: {raw} seen within {self.ttl}s"
                )
            else:
                # Store fingerprint with TTL
                self.redis.setex(redis_key, self.ttl, "1")
                alert["is_duplicate"] = False
                logger.debug(
                    f"New alert fingerprint stored: {fingerprint[:8]}"
                )
        except Exception as e:
            logger.error(f"Redis error: {e}")
            alert["is_duplicate"] = False

        return alert

    def should_store(self, alert: dict) -> bool:
        """
        Decision: store this alert in PostgreSQL?
        Store if: not noise AND not duplicate
        """
        if alert.get("is_noise"):
            logger.debug(
                f"Discarding noise alert rule {alert.get('rule_id')}"
            )
            return False
        if alert.get("is_duplicate"):
            logger.debug(
                f"Discarding duplicate alert {alert.get('alert_id')}"
            )
            return False
        return True
