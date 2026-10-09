"""
import os 
Authentification pour le backend UI.
Login simple avec table users, mots de passe hashés (bcrypt) et jetons JWT.
"""
from datetime import datetime, timedelta
from passlib.context import CryptContext
from jose import jwt, JWTError
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from config import config
from database import query_one, execute

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")


# --- Hachage des mots de passe ---
def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


# --- JWT ---
def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=config.JWT_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, config.JWT_SECRET, algorithm=config.JWT_ALGORITHM)


def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, config.JWT_SECRET, algorithms=[config.JWT_ALGORITHM])
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Jeton invalide ou expiré",
        )


# --- Dépendance : récupérer l'utilisateur courant depuis le jeton ---
def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    payload = decode_token(token)
    username = payload.get("sub")
    if username is None:
        raise HTTPException(status_code=401, detail="Jeton invalide")
    user = query_one(
        "SELECT id, username, full_name, role FROM users WHERE username = %s",
        (username,),
    )
    if user is None:
        raise HTTPException(status_code=401, detail="Utilisateur introuvable")
    return user


# --- Dépendance : exiger le rôle admin ---
def require_admin(user: dict = Depends(get_current_user)) -> dict:
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Accès réservé aux administrateurs")
    return user


# --- Authentifier un utilisateur (login) ---
def authenticate_user(username: str, password: str):
    user = query_one(
        "SELECT id, username, password_hash, full_name, role FROM users WHERE username = %s",
        (username,),
    )
    if not user or not verify_password(password, user["password_hash"]):
        return None
    return user


# --- Création des utilisateurs de démonstration ---
def seed_demo_users():
    """
    Crée quelques utilisateurs de démo s'ils n'existent pas déjà.
    Appelé manuellement une fois (voir setup.py).
    """
    demo_password = os.getenv("DEMO_PASSWORD")
    if not demo_password:
        raise RuntimeError("Set DEMO_PASSWORD in .env before creating demo users")

    demo_users = [
        ("admin",   demo_password, "Administrateur SOC", "admin"),
        ("jawher",  demo_password, "Jawher Yahyaoui",    "analyst"),
        ("analyst", demo_password, "Analyste SOC",       "analyst"),
    ]
    for username, password, full_name, role in demo_users:
        existing = query_one("SELECT id FROM users WHERE username = %s", (username,))
        if existing is None:
            execute(
                "INSERT INTO users (username, password_hash, full_name, role) "
                "VALUES (%s, %s, %s, %s)",
                (username, hash_password(password), full_name, role),
            )
            print(f"  Utilisateur créé : {username} ({role})")
        else:
            print(f"  Utilisateur déjà présent : {username}")
