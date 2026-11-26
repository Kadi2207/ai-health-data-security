import re
from database import get_connection
from auth import set_user_credentials


# Politique de mot de passe stricte (norme ANSSI/NIST : 12+ car., 4 types)
def valider_mot_de_passe(mdp: str) -> bool:
    if len(mdp) < 12:
        return False
    if not re.search(r"[A-Z]", mdp): return False
    if not re.search(r"[a-z]", mdp): return False
    if not re.search(r"[0-9]", mdp): return False
    if not re.search(r"[^A-Za-z0-9]", mdp): return False
    return True


# Mots de passe par défaut LISIBLES, assignés par l'admin.
# Comptes de démo : identifiants mémorisables pour la présentation.
COMPTES_DEMO = {
    "admin1":     "Admin@TCIM2026",
    "medecin1":   "Medecin@TCIM2026",
    "infirmier1": "Infirmier@TCIM26",
    "patient1":   "Patient@TCIM2026",
}

# Mot de passe par défaut commun pour tous les autres comptes.
# Communiqué par l'admin à chaque utilisateur, à changer à la 1re connexion.
MDP_DEFAUT = "Bienvenue@TCIM2026"


def init_all_credentials():
    print("=== Initialisation des comptes sécurisés ===\n")

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT username, role FROM utilisateurs ORDER BY role, username")
    comptes = cursor.fetchall()
    conn.close()

    lignes_liste = ["=== LISTE DES ACCÈS — CONFIDENTIEL (usage admin) ===\n",
                    "Chaque utilisateur doit changer ce mot de passe à sa première connexion.\n\n"]

    for row in comptes:
        username = row["username"]
        role = row["role"]
        # Mot de passe par défaut : lisible pour les comptes de démo, commun pour les autres
        password = COMPTES_DEMO.get(username, MDP_DEFAUT)

        if not valider_mot_de_passe(password):
            print(f"  [!] Mot de passe non conforme pour {username}, ignoré.")
            continue

        set_user_credentials(username, password)
        lignes_liste.append(f"{username:15} | {role:10} | {password}\n")

    # Génération de la liste admin (fichier confidentiel, exclu de Git)
    with open("comptes_acces.txt", "w", encoding="utf-8") as f:
        f.writelines(lignes_liste)

    print(f"{len(comptes)} comptes initialisés (mot de passe par défaut + 2FA).")
    print("\nComptes de démonstration :")
    for u, p in COMPTES_DEMO.items():
        print(f"  {u:12} : {p}")
    print(f"\nTous les autres comptes : mot de passe par défaut « {MDP_DEFAUT} »")
    print("La liste complète des accès a été enregistrée dans : comptes_acces.txt")
    print("Chaque utilisateur devra changer son mot de passe à la première connexion.")


if __name__ == "__main__":
    init_all_credentials()