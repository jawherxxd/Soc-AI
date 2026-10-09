import os
from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(__file__), '.env'))

class Settings:
    # PostgreSQL
    DB_HOST = os.getenv('DB_HOST', 'localhost')
    DB_PORT = int(os.getenv('DB_PORT', 5432))
    DB_NAME = os.getenv('DB_NAME', 'socdb')
    DB_USER = os.getenv('DB_USER', 'socuser')
    DB_PASSWORD = os.getenv('DB_PASSWORD', '')
    DB_URL = f"postgresql://{os.getenv('DB_USER')}:{os.getenv('DB_PASSWORD')}@{os.getenv('DB_HOST', 'localhost')}:{os.getenv('DB_PORT', 5432)}/{os.getenv('DB_NAME', 'socdb')}"

    # Redis
    REDIS_HOST = os.getenv('REDIS_HOST', 'localhost')
    REDIS_PORT = int(os.getenv('REDIS_PORT', 6379))
    REDIS_TTL = int(os.getenv('REDIS_TTL', 60))

    # Wazuh
    WAZUH_HOST = os.getenv('WAZUH_HOST')
    WAZUH_PORT = int(os.getenv('WAZUH_PORT', 55000))
    WAZUH_USER = os.getenv('WAZUH_USER')
    WAZUH_PASSWORD = os.getenv('WAZUH_PASSWORD')

    # AbuseIPDB
    ABUSEIPDB_KEY = os.getenv('ABUSEIPDB_KEY')

    # GeoIP
    GEOIP_DB = os.getenv('GEOIP_DB')

    # NVD
    NVD_API_URL = os.getenv('NVD_API_URL')
    NVD_API_KEY = os.getenv('NVD_API_KEY')

    # NVIDIA LLM
    LLM_PROVIDER = os.getenv('LLM_PROVIDER', 'nvidia')
    LLM_API_KEY = os.getenv('LLM_API_KEY')
    LLM_BASE_URL = os.getenv('LLM_BASE_URL')
    LLM_MODEL = os.getenv('LLM_MODEL')
    LLM_MAX_TOKENS = int(os.getenv('LLM_MAX_TOKENS', 1000))

    # Pipeline
    PIPELINE_HOST = os.getenv('PIPELINE_HOST', '0.0.0.0')
    PIPELINE_PORT = int(os.getenv('PIPELINE_PORT', 8000))

    # Noise filter
    NOISE_RULE_IDS = [
        int(x) for x in os.getenv(
            'NOISE_RULE_IDS', '510,511,512,513,514,1002'
        ).split(',')
    ]
    DEDUP_WINDOW_SECONDS = int(os.getenv('DEDUP_WINDOW_SECONDS', 60))

    # AI Engine
    CORRELATION_WINDOW_SECONDS = int(os.getenv('CORRELATION_WINDOW_SECONDS', 300))
    CASE_SEVERITY_THRESHOLD = int(os.getenv('CASE_SEVERITY_THRESHOLD', 5))
    FP_THRESHOLD = float(os.getenv('FP_THRESHOLD', 0.7))

    # iTop ITSM
    ITOP_URL = os.getenv('ITOP_URL')
    ITOP_USER = os.getenv('ITOP_USER', 'admin')
    ITOP_PASSWORD = os.getenv('ITOP_PASSWORD')
    ITOP_ORG = os.getenv('ITOP_ORG', 'SOC-Lab')
    ITOP_ANALYST_ID = os.getenv('ITOP_ANALYST_ID', '3')
    ITOP_ANALYST_NAME = os.getenv('ITOP_ANALYST_NAME', 'yahyaoui')
    ITOP_ANALYST_FIRSTNAME = os.getenv('ITOP_ANALYST_FIRSTNAME', 'jawher')
    ITOP_TEAM_ID = os.getenv('ITOP_TEAM_ID', '2')
    ITOP_TEAM_NAME = os.getenv('ITOP_TEAM_NAME', 'SOC Tier 1')

settings = Settings()
