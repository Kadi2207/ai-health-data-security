import psycopg2
import psycopg2.extras
import os
from dotenv import load_dotenv

load_dotenv()

PG_HOST = os.getenv("PG_HOST", "localhost")
PG_PORT = os.getenv("PG_PORT", "5432")
PG_DATABASE = os.getenv("PG_DATABASE", "tcim_medical")
PG_USER = os.getenv("PG_USER", "postgres")
PG_PASSWORD = os.getenv("PG_PASSWORD", "")


def get_connection():
    conn = psycopg2.connect(
        host=PG_HOST,
        port=PG_PORT,
        dbname=PG_DATABASE,
        user=PG_USER,
        password=PG_PASSWORD,
        cursor_factory=psycopg2.extras.RealDictCursor
    )
    return conn


def init_db():
    conn = get_connection()
    cursor = conn.cursor()
    with open("data/schema_postgresql.sql", "r", encoding="utf-8") as f:
        cursor.execute(f.read())
    conn.commit()
    conn.close()
    print(f"Base de données PostgreSQL '{PG_DATABASE}' initialisée avec succès.")


def insert_patient(nom, prenom, date_naissance, nir, adresse, medecin_traitant):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO patients (nom, prenom, date_naissance, nir, adresse, medecin_traitant)
        VALUES (%s, %s, %s, %s, %s, %s) RETURNING id
    """, (nom, prenom, date_naissance, nir, adresse, medecin_traitant))
    patient_id = cursor.fetchone()["id"]
    conn.commit()
    conn.close()
    return patient_id


def insert_dossier(patient_id, diagnostic, medicaments, notes, sensitivity_level="low"):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO dossiers_medicaux (patient_id, diagnostic, medicaments, notes, sensitivity_level)
        VALUES (%s, %s, %s, %s, %s) RETURNING id
    """, (patient_id, diagnostic, medicaments, notes, sensitivity_level))
    dossier_id = cursor.fetchone()["id"]
    conn.commit()
    conn.close()
    return dossier_id


def get_all_patients():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM patients")
    rows = cursor.fetchall()
    conn.close()
    return rows


def get_dossier_by_patient(patient_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM dossiers_medicaux WHERE patient_id = %s", (patient_id,))
    row = cursor.fetchone()
    conn.close()
    return row


def update_dossier_encrypted(dossier_id, encrypted_diagnostic,
                              encrypted_medicaments, sensitivity_level,
                              encrypted_notes=None):
    # encrypted_notes=None laisse le champ notes tel quel (COALESCE)
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE dossiers_medicaux
        SET diagnostic = %s, medicaments = %s, notes = COALESCE(%s, notes),
            is_encrypted = 1, sensitivity_level = %s, updated_at = CURRENT_TIMESTAMP
        WHERE id = %s
    """, (encrypted_diagnostic, encrypted_medicaments, encrypted_notes, sensitivity_level, dossier_id))
    conn.commit()
    conn.close()


def insert_utilisateur(nom, prenom, role, username, patient_id=None):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO utilisateurs (nom, prenom, role, username, patient_id)
        VALUES (%s, %s, %s, %s, %s)
    """, (nom, prenom, role, username, patient_id))
    conn.commit()
    conn.close()


def get_utilisateur_by_username(username):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM utilisateurs WHERE username = %s", (username,))
    row = cursor.fetchone()
    conn.close()
    return row


def get_patient_id_of_user(username):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT patient_id FROM utilisateurs WHERE username = %s", (username,))
    row = cursor.fetchone()
    conn.close()
    return row["patient_id"] if row else None


def get_doit_changer_mdp(username):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT doit_changer_mdp FROM utilisateurs WHERE username = %s", (username,))
    row = cursor.fetchone()
    conn.close()
    return row["doit_changer_mdp"] if row else 0


def set_password_and_clear_flag(username, password_hash):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE utilisateurs
        SET password_hash = %s, doit_changer_mdp = 0
        WHERE username = %s
    """, (password_hash, username))
    conn.commit()
    conn.close()


def get_stats_sensitivity():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT sensitivity_level, COUNT(*) as total
        FROM dossiers_medicaux
        GROUP BY sensitivity_level
    """)
    rows = cursor.fetchall()
    conn.close()
    return {row["sensitivity_level"]: row["total"] for row in rows}


def get_stats_access_by_role():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT u.role, l.resultat, COUNT(*) as total
        FROM audit_logs l
        LEFT JOIN utilisateurs u ON l.utilisateur_id = u.username
        GROUP BY u.role, l.resultat
    """)
    rows = cursor.fetchall()
    conn.close()
    result = {}
    for row in rows:
        role = row["role"] or "inconnu"
        if role not in result:
            result[role] = {"accordé": 0, "refusé": 0}
        if row["resultat"] in ("accordé", "autorisé", "granted"):
            result[role]["accordé"] += row["total"]
        else:
            result[role]["refusé"] += row["total"]
    return result


def get_stats_counters():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) as total FROM dossiers_medicaux")
    total_dossiers = cursor.fetchone()["total"]

    cursor.execute("SELECT COUNT(*) as total FROM dossiers_medicaux WHERE is_encrypted = 1")
    total_chiffres = cursor.fetchone()["total"]

    # Accès du jour courant uniquement. Les horodatages sont écrits en texte au
    # format "%Y-%m-%d %H:%M:%S" par l'heure locale Python (audit_log.log_access,
    # deblocage_secours.py) : on filtre sur le préfixe de date calculé avec la
    # même horloge, pour éviter tout écart de fuseau avec le serveur PostgreSQL.
    from datetime import datetime
    prefixe_jour = datetime.now().strftime("%Y-%m-%d") + "%"
    cursor.execute(
        "SELECT COUNT(*) as total FROM audit_logs WHERE timestamp LIKE %s",
        (prefixe_jour,)
    )
    acces_aujourd_hui = cursor.fetchone()["total"]

    try:
        cursor.execute("SELECT COUNT(*) as total FROM alertes")
        total_alertes = cursor.fetchone()["total"]
    except Exception:
        total_alertes = 0

    conn.close()
    return {
        "total_dossiers": total_dossiers,
        "total_chiffres": total_chiffres,
        "acces_aujourd_hui": acces_aujourd_hui,
        "total_alertes": total_alertes
    }
# ── Création de dossier avec médecin auteur ──────────────────────────────────
def insert_dossier_complet(patient_id, diagnostic, medicaments, notes, medecin_auteur, sensitivity_level="low"):
    """Crée un dossier en enregistrant le médecin qui l'a rédigé."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO dossiers_medicaux (patient_id, diagnostic, medicaments, notes, medecin_auteur, sensitivity_level)
        VALUES (%s, %s, %s, %s, %s, %s) RETURNING id
    """, (patient_id, diagnostic, medicaments, notes, medecin_auteur, sensitivity_level))
    dossier_id = cursor.fetchone()["id"]
    conn.commit()
    conn.close()
    return dossier_id


def update_dossier_contenu(dossier_id, diagnostic, medicaments, notes, medecin_auteur):
    """Met à jour le contenu d'un dossier existant + trace le médecin et la date."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE dossiers_medicaux
        SET diagnostic = %s, medicaments = %s, notes = %s,
            medecin_auteur = %s, is_encrypted = 0, updated_at = CURRENT_TIMESTAMP
        WHERE id = %s
    """, (diagnostic, medicaments, notes, medecin_auteur, dossier_id))
    conn.commit()
    conn.close()


def get_patients_sans_dossier():
    """Liste les patients qui n'ont pas encore de dossier médical."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT p.* FROM patients p
        LEFT JOIN dossiers_medicaux d ON p.id = d.patient_id
        WHERE d.id IS NULL
        ORDER BY p.nom
    """)
    rows = cursor.fetchall()
    conn.close()
    return rows


def get_dossier_by_id(dossier_id):
    """Récupère un dossier par son id (pour l'affichage/modification)."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM dossiers_medicaux WHERE id = %s", (dossier_id,))
    row = cursor.fetchone()
    conn.close()
    return row

# ── Entrées de dossier (historique médical inaltérable) ──────────────────────
def insert_entree(patient_id, diagnostic, medicaments, notes, medecin_auteur, sensitivity_level="low"):
    """Ajoute une nouvelle entrée à l'historique d'un patient.
    N'écrase JAMAIS les entrées précédentes — chaque consultation est figée."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO entrees_dossier (patient_id, diagnostic, medicaments, notes, medecin_auteur, sensitivity_level)
        VALUES (%s, %s, %s, %s, %s, %s) RETURNING id
    """, (patient_id, diagnostic, medicaments, notes, medecin_auteur, sensitivity_level))
    entree_id = cursor.fetchone()["id"]
    conn.commit()
    conn.close()
    return entree_id


def update_entree_encrypted(entree_id, encrypted_diagnostic, encrypted_medicaments, sensitivity_level,
                            encrypted_notes=None):
    """Chiffre le contenu d'une entrée après sa classification.
    encrypted_notes=None laisse le champ notes tel quel (COALESCE)."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE entrees_dossier
        SET diagnostic = %s, medicaments = %s, notes = COALESCE(%s, notes),
            is_encrypted = 1, sensitivity_level = %s
        WHERE id = %s
    """, (encrypted_diagnostic, encrypted_medicaments, encrypted_notes, sensitivity_level, entree_id))
    conn.commit()
    conn.close()


def update_notes_chiffrees(table, ligne_id, encrypted_notes):
    """Réécrit seulement le champ notes (migration des notes restées en clair)."""
    if table not in ("dossiers_medicaux", "entrees_dossier"):
        raise ValueError(f"Table non autorisée : {table}")
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(f"UPDATE {table} SET notes = %s WHERE id = %s", (encrypted_notes, ligne_id))
    conn.commit()
    conn.close()


def get_entrees_by_patient(patient_id):
    """Retourne toutes les entrées d'un patient, de la plus récente à la plus ancienne."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT * FROM entrees_dossier
        WHERE patient_id = %s
        ORDER BY created_at DESC
    """, (patient_id,))
    rows = cursor.fetchall()
    conn.close()
    return rows