"""
Backend UI de la plateforme SOC.
Application FastAPI SÉPARÉE du pipeline (port 8080).
Lit la base PostgreSQL du pipeline en isolation, sans jamais modifier
son code ni ses tables existantes.
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from config import config
from database import init_pool
from routes_auth import router as auth_router
from routes_incidents import router as incidents_router
from routes_actions import router as actions_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Au démarrage : initialiser le pool de connexions
    init_pool()
    print(f"Backend UI démarré sur le port {config.UI_PORT}")
    yield
    # À l'arrêt : rien de spécial


app = FastAPI(
    title="SOC Platform UI",
    description="Interface de supervision du SOC augmenté par IA",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS — autoriser le frontend React à appeler l'API
app.add_middleware(
    CORSMiddleware,
    allow_origins=config.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Enregistrer les routes
app.include_router(auth_router)
app.include_router(incidents_router)
app.include_router(actions_router)


@app.get("/")
def health():
    return {"status": "running", "service": "SOC Platform UI Backend"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host=config.UI_HOST, port=config.UI_PORT, reload=True)
