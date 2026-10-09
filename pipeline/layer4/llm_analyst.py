import json
import requests
from loguru import logger
from config.settings import settings


class LLMAnalyst:
    """
    Sends correlated alert groups to NVIDIA NIM LLM.
    LLM acts as a SOC analyst and returns:
    - True/False positive decision
    - Severity level
    - Attack pattern description
    - Case title
    - Affected assets
    - Remediation steps
    """

    def __init__(self):
        self.api_key = settings.LLM_API_KEY
        self.base_url = settings.LLM_BASE_URL
        self.model = settings.LLM_MODEL
        self.max_tokens = settings.LLM_MAX_TOKENS
        logger.info(f"LLM Analyst ready — model: {self.model}")

    def analyze(self, alert_group: list) -> dict:
        """
        Send alert group to LLM for analysis.
        Returns structured case dict or None if failed.
        """
        if not alert_group:
            return None

        prompt = self._build_prompt(alert_group)

        try:
            response = requests.post(
                f"{self.base_url}/chat/completions",
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json"
                },
                json={
                    "model": self.model,
                    "messages": [
                        {
                            "role": "system",
                            "content": (
                                "You are an expert SOC analyst "
                                "with 10 years of experience. "
                                "Analyze security incidents and "
                                "respond ONLY with valid JSON. "
                                "No explanation. No markdown. "
                                "No code blocks. JSON only."
                            )
                        },
                        {
                            "role": "user",
                            "content": prompt
                        }
                    ],
                    "max_tokens": self.max_tokens,
                    "temperature": 0.1
                },
                timeout=60
            )

            if response.status_code == 200:
                content = response.json()[
                    "choices"
                ][0]["message"]["content"]
                result = self._parse_response(content)
                if result:
                    logger.info(
                        f"LLM analysis complete — "
                        f"TP: {result.get('is_true_positive')} | "
                        f"severity: {result.get('severity')} | "
                        f"title: {result.get('case_title')}"
                    )
                return result
            else:
                logger.error(
                    f"LLM API error {response.status_code}: "
                    f"{response.text[:200]}"
                )
                return None

        except Exception as e:
            logger.error(f"LLM request failed: {e}")
            return None

    def _build_prompt(self, alert_group: list) -> str:
        """Build structured prompt from alert group."""
        n = len(alert_group)
        alerts_text = ""

        for i, alert in enumerate(alert_group[:20]):
            alerts_text += f"""
Alert {i+1}:
  - Agent: {alert.get('agent_name', 'unknown')}
  - Rule: {alert.get('rule_description', 'unknown')}
  - Severity: {alert.get('rule_level', 0)}/15
  - Source IP: {alert.get('src_ip', 'unknown')}
  - Destination IP: {alert.get('dst_ip', 'unknown')}
  - Destination port: {alert.get('dst_port', 'unknown')}
  - Country: {alert.get('country', 'unknown')}
  - Abuse score: {alert.get('abuse_score', 0)}/100
  - Risk score: {alert.get('risk_score', 0)}/100
  - MITRE tactic: {alert.get('mitre_tactic', 'unknown')}
  - MITRE technique: {alert.get('mitre_technique', 'unknown')}
"""

        prompt = f"""Analyze this security incident
containing {n} correlated alerts:
{alerts_text}

Respond with ONLY this JSON structure:
{{
  "is_true_positive": true or false,
  "severity": "low" or "medium" or "high" or "critical",
  "attack_pattern": "brief description of what is happening",
  "case_title": "short descriptive title",
  "affected_assets": ["list of destination IPs"],
  "mitre_tactic": "primary MITRE tactic",
  "mitre_technique": "primary MITRE technique ID",
  "false_positive_reason": "reason if false positive else null",
  "remediation_steps": [
    "step 1",
    "step 2",
    "step 3"
  ]
}}"""
        return prompt

    def _parse_response(self, content: str) -> dict:
        """Parse LLM JSON response safely."""
        try:
            content = content.strip()
            if content.startswith("```"):
                content = content.split("```")[1]
                if content.startswith("json"):
                    content = content[4:]
            content = content.strip()

            result = json.loads(content)

            required = [
                "is_true_positive", "severity",
                "case_title", "remediation_steps"
            ]
            for field in required:
                if field not in result:
                    logger.warning(
                        f"LLM response missing field: {field}"
                    )
                    return None

            return result

        except json.JSONDecodeError as e:
            logger.error(f"LLM JSON parse error: {e}")
            logger.error(f"Raw content: {content[:200]}")
            return None
