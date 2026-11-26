from datetime import datetime
from database import get_connection


def init_audit_tables():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id SERIAL PRIMARY KEY,
            utilisateur_id TEXT NOT NULL,
            action TEXT NOT NULL,
            ressource TEXT DEFAULT 'Dossier Médical',
            resultat TEXT NOT NULL CHECK(resultat IN ('accordé', 'refusé')),
            timestamp TEXT NOT NULL
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alertes (
            id SERIAL PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            message TEXT NOT NULL,
            timestamp TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


def log_access(utilisateur_id, action, ressource=None, resultat="refusé"):
    if resultat.lower() in ("accordé", "granted", "ok", "autorisé"):
        resultat = "accordé"
    else:
        resultat = "refusé"

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO audit_logs (utilisateur_id, action, ressource, resultat, timestamp) VALUES (%s, %s, %s, %s, %s)",
        (str(utilisateur_id), str(action), ressource or "Dossier Médical", resultat,
         datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    )
    conn.commit()
    conn.close()

    if resultat == "refusé":
        try:
            from security_monitor import scan_complet
            scan_complet()
        except Exception:
            pass


def get_all_logs():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT
            l.timestamp,
            l.utilisateur_id as username,
            COALESCE(u.role, 'inconnu') as role,
            l.action,
            COALESCE(l.ressource, 'Dossier Médical') as ressource,
            l.resultat
        FROM audit_logs l
        LEFT JOIN utilisateurs u ON l.utilisateur_id = u.username
        ORDER BY l.id DESC
    """)
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_all_alertes():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, username, message, timestamp FROM alertes ORDER BY id DESC"
    )
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_logs_refuses():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT * FROM audit_logs
        WHERE resultat = 'refusé'
        ORDER BY id DESC
    """)
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]