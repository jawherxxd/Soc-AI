"""
Script d'initialisation à lancer UNE FOIS.
Crée la table users et insère les utilisateurs de démonstration.
Ne touche à aucune table existante.
"""
from database import get_cursor, init_pool
from auth import seed_demo_users


def create_users_table():
    with get_cursor(commit=True) as cur:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id            SERIAL PRIMARY KEY,
                username      VARCHAR(100) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                full_name     VARCHAR(150),
                role          VARCHAR(50) DEFAULT 'analyst',
                created_at    TIMESTAMP WITH TIME ZONE DEFAULT now()
            )
        """)
    print("Table 'users' prête.")


if __name__ == "__main__":
    print("Initialisation du backend UI...")
    init_pool()
    create_users_table()
    print("Création des utilisateurs de démo :")
    seed_demo_users()
    print("\nTerminé. Utilisateurs disponibles :")
    print("  - admin   (rôle admin)")
    print("  - jawher  (rôle analyst)")
    print("  - analyst (rôle analyst)")
