# TCIM — IA appliquée à la sécurité des données de santé
Projet de sécurisation de données de santé, développé lors d'un stage chez Skills4Mind.

> ⚠️ **Projet de démonstration, données 100 % fictives.** Tous les patients, dossiers et numéros NIR sont générés avec Faker. Aucune donnée de santé réelle n'est utilisée. Ce dépôt est une démonstration, pas un logiciel prêt pour la production (voir [Limites connues](#limites-connues)).

---

## Description

**Système de protection des données de santé où une IA de classification détecte automatiquement les informations sensibles et déclenche leur chiffrement, au sein d'une architecture Zero Trust.**

Quand un médecin saisit un dossier, chaque champ est analysé par le classifieur. Le diagnostic et les médicaments jugés sensibles sont chiffrés automatiquement, sans décision manuelle. Autour de ce cœur IA, l'application applique les principes Zero Trust : chaque accès est authentifié, autorisé par rôle, tracé et surveillé.

**Flux principal :**
> Saisie d'un dossier → **Classification IA de la sensibilité** → Chiffrement automatique des champs sensibles → Contrôle d'accès RBAC → Journal d'audit → Détection d'intrusion et blocage automatique

---

## Cœur du projet : la classification par IA

Le classifieur (`src/classifier.py`) est **hybride**. Il combine des règles explicites et un modèle d'apprentissage supervisé, puis fusionne leurs résultats de façon prudente.

| Couche | Rôle | Technique |
|---|---|---|
| 1. Règles déterministes | Repérer à coup sûr les données critiques | Expressions régulières (NIR, dates, e-mails, téléphones, noms de praticiens) + mots-clés médicaux critiques en français et en anglais (VIH, cancer, psychiatrie, stupéfiants…) |
| 2. Modèle d'apprentissage | Repérer les textes médicaux sensibles qu'aucune règle ne couvre | scikit-learn : vectorisation **TF-IDF** (mots et bigrammes) + **Random Forest** (300 arbres, classes équilibrées), sauvegardé dans `data/model.pkl` |
| 3. Fusion | Décider du niveau de sensibilité | Une règle déclenchée donne **élevé**, prioritaire sur le modèle. Sinon : probabilité ≥ 0,7 → **élevé**, ≥ 0,5 → **moyen**, en dessous → **faible** |

- **Principe de précaution :** il suffit d'un seul champ déclenché par une règle pour que tout le dossier passe en sensibilité élevée.
- **Déclenchement du chiffrement :** quand le diagnostic ou les médicaments sont classés sensibles, ils sont chiffrés avec Fernet (AES-128-CBC + HMAC-SHA256). La clé est lue depuis `.env` et n'est jamais versionnée.
- **Ce que le modèle est vraiment :** une classification supervisée classique, entraînée une fois hors ligne (`src/train_model.py`) sur un petit corpus de **197 phrases médicales fictives rédigées en français** (98 sensibles, 99 non sensibles). Sa précision sur le jeu de test est de **82,5 %**, sur 20 % du corpus. Il n'y a ni LLM, ni apprentissage en ligne : le modèle n'apprend pas pendant l'utilisation.
- **Langues :** le modèle n'est utilisé que pour le français. En anglais, seules les règles (bilingues) s'appliquent.

---

## Fonctionnalités

### Protection des données
- **Classification IA** de chaque dossier : sensibilité faible, moyenne ou élevée (voir ci-dessus).
- **Chiffrement automatique** du diagnostic et des médicaments lorsqu'ils sont classés sensibles.

### Authentification
- Mots de passe hachés avec **bcrypt**. Politique stricte : 12 caractères minimum, majuscule, minuscule, chiffre et caractère spécial.
- **Changement de mot de passe obligatoire** à la première connexion.
- **Double authentification TOTP** (pyotp) : QR code à scanner à la première connexion, puis code à 6 chiffres.
- **Appareil de confiance** (facultatif, décoché par défaut) : après une 2FA réussie, l'utilisateur peut dispenser cet appareil de la 2FA pendant 30 jours. **Le mot de passe reste toujours exigé.** Le cookie ne contient qu'un jeton aléatoire signé (HttpOnly, SameSite=Strict) et la base ne stocke que son empreinte SHA-256. L'expiration est fixe et contrôlée côté serveur, et l'appareil est révoqué au déblocage d'un compte.
- **Limitation des tentatives** (Flask-Limiter) : 10 requêtes/minute sur la connexion, la 2FA et l'enregistrement d'appareil.
- Toutes les sessions sont invalidées à chaque redémarrage du serveur.

### Contrôle d'accès et traçabilité
- **RBAC** à 4 rôles : `admin`, `medecin`, `infirmier`, `patient`. Un patient ne peut lire que son propre dossier, quel que soit l'identifiant demandé.
- **Journal d'audit** horodaté de chaque action (accordée ou refusée).

### Détection d'intrusion
Moteur de règles inspiré des SIEM (`src/security_monitor.py`), sur une fenêtre glissante de 5 minutes :

| Menace | Seuil | Gravité | Réaction |
|---|---|---|---|
| Force brute (connexion / 2FA) | 3 échecs | CRITIQUE | Alerte + blocage du compte |
| Password spray (échecs de connexion sur plusieurs comptes) | 3 comptes visés | CRITIQUE | Alerte + blocage des comptes visés |
| Escalade de privilèges (compte patient) | 2 actions non autorisées | CRITIQUE | Alerte + blocage du compte |
| Volume d'accès anormal | 10 actions | ÉLEVÉ | Alerte |

- Aucune exception : un compte administrateur attaqué est bloqué lui aussi.
- **Déblocage par un administrateur** depuis l'interface. Il faut confirmer son mot de passe, choisir une catégorie et écrire un motif détaillé. Chaque déblocage est tracé dans le journal d'audit.
- **Accès de secours** (`deblocage_secours.py`) : si tous les administrateurs sont bloqués, déblocage hors ligne possible uniquement par une personne ayant un accès direct au serveur. L'action est elle aussi tracée dans le journal d'audit.

### Interface
- Tableau de bord : indicateurs, graphiques, journaux, alertes, score de conformité RGPD/HDS.
- Affichage cloisonné selon le rôle connecté.
- **Bilingue FR / EN** (Flask-Babel). Les journaux sont stockés en français et traduits uniquement à l'affichage.
- Mode clair / sombre.
- Toutes les données venant du serveur sont échappées avant insertion dans la page (protection XSS).

---

## Stack technique

| Composant | Technologie |
|-----------|-------------|
| Langage | Python 3 |
| Base de données | PostgreSQL (psycopg2) |
| Application web | Flask, Flask-Babel, Flask-Limiter |
| Classification IA | scikit-learn + regex + mots-clés |
| Chiffrement | `cryptography`, Fernet (AES-128-CBC + HMAC-SHA256) |
| Authentification | bcrypt, pyotp (TOTP), qrcode |
| Contrôle d'accès | RBAC maison Python |
| Données fictives | Faker |
| Versioning | Git / GitHub |

---

## Installation

Prérequis : **Python 3** et un serveur **PostgreSQL** accessible.

Toutes les commandes se lancent **depuis la racine du projet**.

### 1. Cloner le dépôt
```bash
git clone https://github.com/Kadi2207/ai-health-data-security.git
cd ai-health-data-security
```

### 2. Créer l'environnement virtuel et installer les dépendances
```bash
python -m venv venv
venv\Scripts\activate        # Windows
source venv/bin/activate     # Mac/Linux
pip install -r requirements.txt
```

### 3. Configurer les variables d'environnement
```bash
cp .env.example .env
```
Générer une clé secrète et la coller dans `.env` à la place de `your_secret_key_here` :
```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```
Renseigner ensuite les paramètres PostgreSQL (`PG_HOST`, `PG_PORT`, `PG_DATABASE`, `PG_USER`, `PG_PASSWORD`).

### 4. Créer la base PostgreSQL
```bash
createdb -U postgres tcim_medical
```

### 5. Générer les données fictives
```bash
python src/data_generator.py
```
⚠️ Ce script **réinitialise entièrement la base** (suppression puis recréation des tables à partir de `data/schema_postgresql.sql`). Il crée 66 comptes : 1 admin, 6 médecins, 9 infirmiers et 50 patients avec leur dossier.

### 6. Initialiser les comptes
```bash
python src/init_auth.py
```
Ce script attribue les mots de passe initiaux et écrit la liste des accès dans `comptes_acces.txt`. Ce fichier contient des mots de passe en clair : il est exclu de Git et ne doit pas être partagé.

### 7. Lancer l'application
```bash
python src/app.py
```
Accès : **http://localhost:5000**

À chaque démarrage, les dossiers sensibles qui ne sont pas encore chiffrés le sont automatiquement.

---

## Comptes de démonstration

> 🚨 **Ces comptes servent uniquement à la DÉMONSTRATION, sur des données fictives.** Leurs mots de passe sont publics, puisqu'ils sont écrits dans `src/init_auth.py`. Ils doivent être changés à la première connexion (l'application l'impose) et **ne doivent jamais être utilisés tels quels sur un déploiement réel.**

| Identifiant | Rôle | Mot de passe initial |
|---|---|---|
| `admin1` | Administrateur | `Admin@TCIM2026` |
| `medecin1` | Médecin | `Medecin@TCIM2026` |
| `infirmier1` | Infirmier | `Infirmier@TCIM26` |
| `patient1` | Patient | `Patient@TCIM2026` |

Tous les autres comptes reçoivent le mot de passe initial commun défini dans `src/init_auth.py` (`MDP_DEFAUT`).

Parcours à la première connexion : mot de passe initial → nouveau mot de passe → scan du QR code dans une application d'authentification (Google Authenticator, Microsoft Authenticator…) → code 2FA.

---

## Démonstration de sécurité

Pendant que l'application tourne, lancer dans un **second terminal** :
```bash
python attaque.py
```
Ce script simule une attaque coordonnée sur plusieurs vecteurs en parallèle : force brute, password spray, escalade de privilèges et volume anormal. Le tableau de bord affiche les alertes et les blocages en temps réel.

Autres scripts :
- `python verif.py` : affiche les menaces détectées dans la fenêtre courante et lance un scan.
- `python deblocage_secours.py` : déblocage de secours (break-glass) des administrateurs. Demande une confirmation et trace l'action.

---

## Tests

```bash
pip install pytest
python -m pytest tests
```
Les tests couvrent la classification (`tests/test_classifier.py`) et le chiffrement (`tests/test_encryption.py`). Les tests de chiffrement nécessitent une `SECRET_KEY` valide dans `.env`.

---

## Traductions (FR / EN)

Les catalogues sont dans `translations/`. Après une modification des textes :
```bash
pybabel extract -F babel.cfg -o messages.pot .
pybabel update -i messages.pot -d translations
pybabel compile -d translations
```

---

## Structure du dépôt
```
ai-health-data-security/
├── src/
│   ├── app.py              # Application Flask (routes, sessions, limitation des tentatives)
│   ├── auth.py             # Authentification : bcrypt, TOTP, QR code
│   ├── trusted_device.py   # Appareils de confiance (2FA allégée, mot de passe toujours exigé)
│   ├── rbac.py             # Contrôle d'accès par rôle
│   ├── audit_log.py        # Journal d'audit horodaté
│   ├── security_monitor.py # Détection d'intrusion et blocage automatique
│   ├── classifier.py       # Classification IA des données sensibles
│   ├── train_model.py      # Entraînement du modèle (génère data/model.pkl)
│   ├── encryption.py       # Chiffrement Fernet (AES-128-CBC + HMAC-SHA256)
│   ├── main_pipeline.py    # Pipeline complet intégré
│   ├── database.py         # Accès PostgreSQL
│   ├── data_generator.py   # Génération des données fictives
│   └── init_auth.py        # Initialisation des comptes (démo)
├── templates/              # Pages HTML (Jinja2)
├── static/                 # CSS et JavaScript (thème, traduction, interface)
├── translations/           # Catalogues FR / EN (Flask-Babel)
├── data/
│   ├── schema_postgresql.sql
│   ├── schema.sql          # Ancien schéma SQLite (historique)
│   ├── keywords_medicaux.txt
│   └── model.pkl           # Modèle de classification entraîné
├── tests/
├── attaque.py              # Démonstration d'attaque multi-vecteurs
├── verif.py                # Diagnostic du moteur de détection
├── deblocage_secours.py    # Accès de secours (break-glass)
├── babel.cfg / messages.pot
├── requirements.txt
├── .env.example
└── .gitignore
```

---

## Limites connues

Ce projet est une démonstration. Points connus, assumés ou en cours :

- **Export PDF du rapport de conformité (`/rapport-pdf`) : en cours de correction.** Il ne fonctionne pas dans la version actuelle.
- **Modèle d'IA entraîné sur un petit corpus** (197 phrases fictives, français uniquement). Ses 82,5 % de précision donnent un ordre de grandeur, pas une garantie : c'est pour cela que les règles déterministes restent prioritaires.
- Le champ **« notes »** est analysé par le classifieur mais **n'est pas chiffré en base** : seuls le diagnostic et les médicaments le sont. Par ailleurs, un dossier est d'abord enregistré, puis chiffré juste après sa classification.
- **Serveur de développement Flask** (`debug=True`, écoute sur toutes les interfaces) : à utiliser en local uniquement. Un déploiement réel demanderait un serveur WSGI, HTTPS et `debug` désactivé.
- **Comptes de démonstration** aux mots de passe publics (voir ci-dessus).
- La même `SECRET_KEY` sert au chiffrement Fernet et à la signature des sessions. En production, il faudrait deux clés distinctes, gérées par un coffre de secrets.
- Les compteurs de Flask-Limiter sont gardés en mémoire : ils repartent de zéro au redémarrage et ne sont pas partagés entre plusieurs processus.
- La page de connexion distingue « utilisateur introuvable » et « mot de passe incorrect », ce qui permet de deviner les identifiants existants. Amélioration prévue.
- `data/model.pkl` est chargé avec `pickle` : ne le remplacer que par un fichier de confiance, ou le régénérer avec `python src/train_model.py`.

---

## Conformité

- **RGPD** : données fictives uniquement, chiffrement des données sensibles, journal d'audit, accès d'un patient limité à son propre dossier.
- **HDS** : contrôle d'accès par rôle, double authentification, traçabilité complète, détection d'intrusion, clés gardées hors du dépôt.
