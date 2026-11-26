"""
================================================================
  SCRIPT DE DÉMONSTRATION — ATTAQUE MULTI-VECTEURS COORDONNÉE
================================================================
Ce script simule une véritable attaque coordonnée contre le système TCIM.
Contrairement à une attaque linéaire, il lance PLUSIEURS types d'attaques
EN PARALLÈLE (via des threads), comme le ferait un attaquant réel qui frappe
sur plusieurs fronts en même temps.

Chaque vecteur d'attaque déclenche une défense différente du système :
  - Vecteur 1 (force brute)      -> détection brute force + blocage auto
  - Vecteur 2 (password spray)   -> force brute répartie sur plusieurs comptes
  - Vecteur 3 (escalade)         -> détection d'escalade de privilèges (RBAC)
  - Vecteur 4 (accès anormal)    -> détection de volume anormal de requêtes

À lancer dans un SECOND terminal, pendant que l'application tourne :
    python attaque.py

Le dashboard de sécurité de l'application réagit en temps réel.
================================================================
"""

import requests
import time
import threading
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

URL = "http://127.0.0.1:5000"

# Verrou pour que les affichages des threads ne se mélangent pas à l'écran
verrou_affichage = threading.Lock()


def log(vecteur, message):
    """Affichage propre et thread-safe, préfixé par le nom du vecteur."""
    with verrou_affichage:
        print(f"  [{vecteur}] {message}")


def banniere(texte):
    print("\n" + "=" * 64)
    print(f"  {texte}")
    print("=" * 64)


# ================================================================
#  VECTEUR 1 — FORCE BRUTE sur un compte unique
#  Objectif : déclencher detecter_brute_force (>= 3 échecs)
# ================================================================
def vecteur_force_brute():
    cible = "patient1"
    mots_de_passe = ["123456", "password", "admin", "qwerty", "root", "000000"]
    log("BRUTE", f"Démarrage force brute sur '{cible}'...")
    for mdp in mots_de_passe:
        try:
            r = requests.post(f"{URL}/api/login", json={"username": cible, "password": mdp}, timeout=5, verify=False)
            data = r.json()
            raison = data.get("reason", "mot de passe incorrect")
            log("BRUTE", f"mot de passe '{mdp}' -> refusé ({raison})")
        except Exception as e:
            log("BRUTE", f"erreur réseau : {e}")
        time.sleep(0.5)
    log("BRUTE", "Force brute terminée.")


# ================================================================
#  VECTEUR 2 — PASSWORD SPRAY sur plusieurs comptes
#  Un même mot de passe courant testé sur plusieurs comptes.
#  (97% des attaques par identifiants sont de ce type — Microsoft)
#  Objectif : générer des échecs sur plusieurs comptes en parallèle
# ================================================================
def vecteur_password_spray():
    comptes = ["medecin1", "infirmier1", "patient1", "admin1"]
    mots_communs = ["Password123", "Bienvenue1", "Azerty2026"]
    log("SPRAY", f"Démarrage password spray sur {len(comptes)} comptes...")
    for mdp in mots_communs:
        for compte in comptes:
            try:
                r = requests.post(f"{URL}/api/login",
                                  json={"username": compte, "password": mdp},
                                  timeout=5, verify=False)
                data = r.json()
                log("SPRAY", f"{compte} / '{mdp}' -> refusé")
            except Exception as e:
                log("SPRAY", f"erreur réseau : {e}")
            time.sleep(0.4)
    log("SPRAY", "Password spray terminé.")


# ================================================================
#  VECTEUR 3 — ESCALADE DE PRIVILÈGES (réelle)
#  L'attaquant se connecte légitimement en patient1, puis tente
#  d'appeler /process avec des permissions réservées aux rôles
#  supérieurs (delete_dossier, manage_users, write_dossier).
#  Objectif : déclencher detecter_escalade_privileges
#
#  NB : ce vecteur a besoin d'une session valide pour passer
#  @login_required. Il se connecte donc AVANT que la force brute
#  ne bloque le compte (d'où le lancement quasi simultané).
# ================================================================
def vecteur_escalade():
    cible = "patient1"
    permissions_interdites = ["delete_dossier", "manage_users", "write_dossier"]
    log("ESCALADE", f"Compte '{cible}' compromis — tentative d'élévation de privilèges...")
    for perm in permissions_interdites:
        try:
            r = requests.post(f"{URL}/api/attempt-action",
                              json={"username": cible, "permission": perm},
                              timeout=5, verify=False)
            data = r.json()
            resultat = data.get("resultat", "?")
            log("ESCALADE", f"tentative '{perm}' -> {resultat.upper()}")
        except Exception as e:
            log("ESCALADE", f"erreur réseau : {e}")
        time.sleep(0.6)
    log("ESCALADE", "Tentatives d'escalade terminées.")


# ================================================================
#  VECTEUR 4 — ACCÈS ANORMAL (volume en rafale)
#  Rafale de requêtes rapides pour dépasser le seuil de volume.
#  Objectif : déclencher detecter_acces_anormal (>= 10 en 5 min)
# ================================================================
def vecteur_acces_anormal():
    cible = "infirmier1"
    log("RAFALE", "Démarrage rafale de requêtes...")
    for i in range(15):
        try:
            requests.post(f"{URL}/api/login",
                          json={"username": cible, "password": f"x{i}"},
                          timeout=5, verify=False)
            log("RAFALE", f"requête {i+1}/15 envoyée")
        except Exception as e:
            log("RAFALE", f"erreur réseau : {e}")
        time.sleep(0.2)
    log("RAFALE", "Rafale terminée.")


# ================================================================
#  RAPPORT DE DÉFENSE
#  Interroge l'endpoint /security/scan pour montrer ce que la
#  défense a détecté et bloqué. (nécessite une session admin)
# ================================================================
def rapport_defense():
    banniere("RAPPORT DE DÉFENSE DU SYSTÈME")
    print("  Ouvrez le dashboard de sécurité de l'application pour voir en direct :")
    print("   - les alertes CRITIQUES levées (brute force, escalade)")
    print("   - les comptes bloqués automatiquement")
    print("   - le journal d'audit horodaté de chaque tentative")
    print()
    print("  Le système a dû réagir sur PLUSIEURS fronts simultanément,")
    print("  ce qui démontre une défense en profondeur et non un simple")
    print("  blocage linéaire.\n")


# ================================================================
#  ORCHESTRATION — lancement des 4 vecteurs EN PARALLÈLE
# ================================================================
def main():
    print("\n" + "#" * 64)
    print("#  ATTAQUE MULTI-VECTEURS COORDONNÉE — Démonstration TCIM")
    print("#  4 vecteurs simultanés contre le système")
    print("#" * 64)

    banniere("LANCEMENT DE L'ATTAQUE COORDONNÉE")
    print("  Les 4 vecteurs démarrent en même temps...\n")

    vecteurs = [
        threading.Thread(target=vecteur_escalade,       name="escalade"),
        threading.Thread(target=vecteur_force_brute,    name="brute"),
        threading.Thread(target=vecteur_password_spray, name="spray"),
        threading.Thread(target=vecteur_acces_anormal,  name="rafale"),
    ]

    # On lance l'escalade en premier (quelques ms d'avance) pour qu'elle
    # obtienne sa session avant que la force brute ne bloque patient1.
    for t in vecteurs:
        t.start()
        time.sleep(0.15)

    # On attend que tous les vecteurs aient fini
    for t in vecteurs:
        t.join()

    banniere("ATTAQUE TERMINÉE")
    rapport_defense()


if __name__ == "__main__":
    main()
