"""
Moteur de détection d'intrusion (inspiré des principes SIEM).
Analyse les logs d'audit en temps réel et détecte les menaces de sécurité
selon des règles déterministes, classe par gravité et déclenche le blocage.
"""

from datetime import datetime, timedelta
from database import get_connection

SEUIL_BRUTE_FORCE = 3
SEUIL_ESCALADE = 2
SEUIL_ACCES_ANORMAL = 10
FENETRE_MINUTES = 5

GRAVITE = {
    "brute_force": "CRITIQUE",
    "escalade_privileges": "CRITIQUE",
    "acces_anormal": "ÉLEVÉ",
    "2fa_force": "CRITIQUE",
    "password_spray": "CRITIQUE",
}


def _fenetre_temporelle():
    limite = datetime.now() - timedelta(minutes=FENETRE_MINUTES)
    return limite.strftime("%Y-%m-%d %H:%M:%S")


def detecter_brute_force(conn):
    cursor = conn.cursor()
    limite = _fenetre_temporelle()
    cursor.execute("""
        SELECT utilisateur_id, COUNT(*) as echecs
        FROM audit_logs
        WHERE resultat = 'refusé'
          AND (action LIKE '%%connexion%%' OR action LIKE '%%2FA%%' OR action LIKE '%%login%%')
          AND timestamp >= %s
        GROUP BY utilisateur_id
        HAVING COUNT(*) >= %s
    """, (limite, SEUIL_BRUTE_FORCE))
    menaces = []
    for row in cursor.fetchall():
        menaces.append({
            "type": "brute_force",
            "gravite": GRAVITE["brute_force"],
            "utilisateur": row["utilisateur_id"],
            "details": f"{row['echecs']} tentatives de connexion échouées en {FENETRE_MINUTES} min",
            "compteur": row["echecs"]
        })
    return menaces

def detecter_password_spray(conn):
    """Détecte un password spray (plusieurs comptes visés) ET identifie
    les comptes concernés pour permettre leur blocage."""
    cursor = conn.cursor()
    limite = _fenetre_temporelle()
    cursor.execute("""
        SELECT DISTINCT utilisateur_id
        FROM audit_logs
        WHERE resultat = 'refusé'
          AND (action LIKE '%%connexion%%' OR action LIKE '%%login%%')
          AND timestamp >= %s
    """, (limite,))
    comptes = [row["utilisateur_id"] for row in cursor.fetchall()]
    menaces = []
    if len(comptes) >= 3:
        menaces.append({
            "type": "password_spray",
            "gravite": "CRITIQUE",
            "utilisateur": "multi-comptes",
            "details": f"Password spray détecté : {len(comptes)} comptes visés simultanément",
            "compteur": len(comptes),
            "comptes_cibles": comptes
        })
    return menaces

def detecter_escalade_privileges(conn):
    cursor = conn.cursor()
    limite = _fenetre_temporelle()
    cursor.execute("""
        SELECT l.utilisateur_id, COUNT(*) as tentatives
        FROM audit_logs l
        LEFT JOIN utilisateurs u ON l.utilisateur_id = u.username
        WHERE l.resultat = 'refusé'
          AND u.role = 'patient'
          AND (l.action LIKE '%%delete%%' OR l.action LIKE '%%write%%'
               OR l.action LIKE '%%manage%%' OR l.action LIKE '%%forçage%%'
               OR l.action LIKE '%%RBAC%%')
          AND l.timestamp >= %s
        GROUP BY l.utilisateur_id
        HAVING COUNT(*) >= %s
    """, (limite, SEUIL_ESCALADE))
    menaces = []
    for row in cursor.fetchall():
        menaces.append({
            "type": "escalade_privileges",
            "gravite": GRAVITE["escalade_privileges"],
            "utilisateur": row["utilisateur_id"],
            "details": f"{row['tentatives']} tentatives d'action non autorisée (escalade de privilèges)",
            "compteur": row["tentatives"]
        })
    return menaces


def detecter_acces_anormal(conn):
    cursor = conn.cursor()
    limite = _fenetre_temporelle()
    cursor.execute("""
        SELECT utilisateur_id, COUNT(*) as acces
        FROM audit_logs
        WHERE timestamp >= %s
        GROUP BY utilisateur_id
        HAVING COUNT(*) >= %s
    """, (limite, SEUIL_ACCES_ANORMAL))
    menaces = []
    for row in cursor.fetchall():
        menaces.append({
            "type": "acces_anormal",
            "gravite": GRAVITE["acces_anormal"],
            "utilisateur": row["utilisateur_id"],
            "details": f"Volume d'accès anormal : {row['acces']} actions en {FENETRE_MINUTES} min",
            "compteur": row["acces"]
        })
    return menaces


def analyser_menaces():
    conn = get_connection()
    menaces = []
    menaces += detecter_brute_force(conn)
    menaces += detecter_password_spray(conn)
    menaces += detecter_escalade_privileges(conn)
    menaces += detecter_acces_anormal(conn)
    conn.close()
    return menaces


def enregistrer_alertes(menaces):
    if not menaces:
        return 0
    conn = get_connection()
    cursor = conn.cursor()
    nb_nouvelles = 0
    for m in menaces:
        message = f"[{m['gravite']}] {m['type'].replace('_', ' ').title()} — {m['details']}"

        # ── BLOCAGE : fait à CHAQUE scan si menace critique ──
        # (indépendant de l'existence de l'alerte, pour un blocage fiable)
        if m["gravite"] == "CRITIQUE":
            if m["type"] == "password_spray" and "comptes_cibles" in m:
                for compte_cible in m["comptes_cibles"]:
                    bloquer_compte(cursor, compte_cible)
            else:
                bloquer_compte(cursor, m["utilisateur"])

        # ── ALERTE : enregistrée une seule fois par type/compte ──
        cursor.execute("""
            SELECT id FROM alertes WHERE username = %s AND message LIKE %s
        """, (m["utilisateur"], f"%{m['type'].replace('_', ' ').title()}%"))
        if cursor.fetchone() is None:
            cursor.execute("""
                INSERT INTO alertes (username, message, timestamp)
                VALUES (%s, %s, %s)
                ON CONFLICT (username) DO UPDATE
                SET message = EXCLUDED.message, timestamp = EXCLUDED.timestamp
            """, (m["utilisateur"], message,
                  datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
            nb_nouvelles += 1
    conn.commit()
    conn.close()
    return nb_nouvelles


def bloquer_compte(cursor, username):
    """Bloque un compte suite à une menace critique.
    Aucune exception : même l'admin est bloqué si attaqué (principe : personne
    n'est au-dessus des règles). L'admin dispose d'un accès de secours hors-ligne
    (break-glass) pour reprendre la main — voir deblocage_secours.py."""
    cursor.execute("""
        UPDATE utilisateurs SET est_bloque = 1 WHERE username = %s
    """, (username,))


def compte_est_bloque(username):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT est_bloque FROM utilisateurs WHERE username = %s", (username,))
    row = cursor.fetchone()
    conn.close()
    if row is None:
        return False
    return bool(row["est_bloque"])


def scan_complet():
    menaces = analyser_menaces()
    nb_nouvelles = enregistrer_alertes(menaces)
    return {
        "menaces_detectees": len(menaces),
        "nouvelles_alertes": nb_nouvelles,
        "menaces": menaces
    }


if __name__ == "__main__":
    print("=== Scan de sécurité ===")
    rapport = scan_complet()
    print(f"Menaces détectées : {rapport['menaces_detectees']}")
    print(f"Nouvelles alertes : {rapport['nouvelles_alertes']}")
    for m in rapport["menaces"]:
        print(f"  [{m['gravite']}] {m['utilisateur']} — {m['details']}")