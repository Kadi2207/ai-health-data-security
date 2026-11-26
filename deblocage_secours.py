"""
=================================================================
  ACCÈS DE SECOURS — "BREAK-GLASS" (déblocage hors-ligne)
=================================================================
Ce script permet de débloquer un compte administrateur directement
sur le serveur, SANS passer par l'interface web (qui est verrouillée
quand l'admin est bloqué).

Principe de sécurité : ce script ne peut être exécuté QUE par une
personne ayant un accès physique/direct au serveur (accès root).
Un attaquant distant, lui, n'y a pas accès. C'est le dernier
rempart de récupération du système.

Usage : python deblocage_secours.py
=================================================================
"""
import sys
sys.path.insert(0, "src")
from database import get_connection
from datetime import datetime


def deblocage_secours():
    print("=" * 60)
    print("  ACCÈS DE SECOURS — Déblocage administrateur")
    print("=" * 60)

    conn = get_connection()
    cursor = conn.cursor()

    # Lister les admins bloqués
    cursor.execute("SELECT username FROM utilisateurs WHERE role = 'admin' AND est_bloque = 1")
    admins_bloques = [row["username"] for row in cursor.fetchall()]

    if not admins_bloques:
        print("  Aucun compte administrateur n'est actuellement bloqué.")
        conn.close()
        return

    print(f"  Comptes administrateurs bloqués : {', '.join(admins_bloques)}")
    confirmation = input("  Confirmer le déblocage de secours ? (oui/non) : ").strip().lower()

    if confirmation != "oui":
        print("  Déblocage annulé.")
        conn.close()
        return

    for admin in admins_bloques:
        cursor.execute("UPDATE utilisateurs SET est_bloque = 0 WHERE username = %s", (admin,))
        # Traçabilité : l'action de secours est journalisée
        cursor.execute("""
            INSERT INTO audit_logs (utilisateur_id, action, ressource, resultat, timestamp)
            VALUES (%s, %s, %s, %s, %s)
        """, (admin,
              "Déblocage de secours (break-glass) via accès serveur direct",
              "Accès de secours hors-ligne",
              "accordé",
              datetime.now().strftime("%Y-%m-%d %H:%M:%S")))

    conn.commit()
    conn.close()
    print(f"  ✅ {len(admins_bloques)} compte(s) administrateur débloqué(s).")
    print("  L'action a été tracée dans le journal d'audit.")


if __name__ == "__main__":
    deblocage_secours()