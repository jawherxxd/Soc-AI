"""
Configuration du backend UI (SOC Platform).
Backend SÉPARÉ du pipeline — lit la même base PostgreSQL en isolation totale.
Aucune dépendance au code du pipeline existant.

Les paramètres sont lus depuis un fichier .env (voir .env.example).
"""
import os
from dotenv import load_dotenv

# Charge automatiquement le fichier .env situé à côté de ce fichier
load_dotenv()

class Config:
    # --- Base de données (mêmes accès que le pipeline, en lecture) ---
    DB_HOST = os.getenv("DB_HOST", "localhost")
    DB_PORT = int(os.getenv("DB_PORT", 5432))
    DB_NAME = os.getenv("DB_NAME", "socdb")
    DB_USER = os.getenv("DB_USER", "socuser")
    DB_PASSWORD = os.getenv("DB_PASSWORD", "CHANGE_ME")  # à définir via variable d'env

    # --- Serveur UI backend ---
    UI_HOST = os.getenv("UI_HOST", "0.0.0.0")
    UI_PORT = int(os.getenv("UI_PORT", 8080))  # port DIFFÉRENT du webhook (8000)

    # --- Authentification (login simple) ---
    JWT_SECRET = os.getenv("JWT_SECRET", "change-this-secret-key-in-production")
    JWT_ALGORITHM = "HS256"
    JWT_EXPIRE_MINUTES = 480  # 8 heures

    # --- iTop (pour la traçabilité — Option hybride) ---
    ITOP_URL = os.getenv("ITOP_URL", "http://10.10.10.200/webservices/rest.php")
    ITOP_USER = os.getenv("ITOP_USER", "soc_api")
    ITOP_PASSWORD = os.getenv("ITOP_PASSWORD", "CHANGE_ME")
    ITOP_VERSION = "1.3"

    # --- n8n (déclenchement direct du playbook containment — Option 1) ---
    N8N_CONTAINMENT_URL = os.getenv(
        "N8N_CONTAINMENT_URL", "http://localhost:5678/webhook/containment"
    )

    # --- CORS (autoriser le frontend React) ---
    CORS_ORIGINS = ["*"]  # en dev ; à restreindre en prod

config = Config()
