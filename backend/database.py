"""
Connexion PostgreSQL pour le backend UI.
Réécriture propre et indépendante (n'importe rien du pipeline).
Utilise un pool de connexions pour de meilleures performances.
"""
import psycopg2
from psycopg2.extras import RealDictCursor
from psycopg2 import pool
from contextlib import contextmanager
from config import config

# Pool de connexions (min 1, max 10) — créé une fois au démarrage
_connection_pool = None


def init_pool():
    """Initialise le pool de connexions au démarrage."""
    global _connection_pool
    if _connection_pool is None:
        _connection_pool = pool.SimpleConnectionPool(
            1, 10,
            host=config.DB_HOST,
            port=config.DB_PORT,
            dbname=config.DB_NAME,
            user=config.DB_USER,
            password=config.DB_PASSWORD,
        )
    return _connection_pool


@contextmanager
def get_cursor(commit=False):
    """
    Fournit un curseur via le pool, avec gestion propre.
    Les résultats sont retournés sous forme de dictionnaires (RealDictCursor).
    """
    global _connection_pool
    if _connection_pool is None:
        init_pool()

    conn = _connection_pool.getconn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            yield cur
            if commit:
                conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        _connection_pool.putconn(conn)


def query_all(sql, params=None):
    """Exécute une requête SELECT et retourne toutes les lignes."""
    with get_cursor() as cur:
        cur.execute(sql, params or ())
        return cur.fetchall()


def query_one(sql, params=None):
    """Exécute une requête SELECT et retourne une seule ligne."""
    with get_cursor() as cur:
        cur.execute(sql, params or ())
        return cur.fetchone()


def execute(sql, params=None):
    """Exécute une requête d'écriture (INSERT/UPDATE) avec commit."""
    with get_cursor(commit=True) as cur:
        cur.execute(sql, params or ())
        # Retourne la ligne si RETURNING est utilisé
        if cur.description:
            return cur.fetchone()
        return None
