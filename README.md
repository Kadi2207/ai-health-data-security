<p align="center">
  <img src="assets/header.svg" alt="En-tête : TCIM, IA appliquée à la sécurité des données de santé" width="100%">
</p>

# TCIM : IA appliquée à la sécurité des données de santé

<a href="https://drive.google.com/file/d/13N5upENpWyv9IF96Au_A_JO1EgVglR6O/view?usp=sharing"><img src="assets/demo-video.svg" alt="Voir la démo vidéo"></a>

Projet de sécurisation de données de santé, développé lors d'un stage chez Skills4Mind.

**Une IA de classification détecte automatiquement les données sensibles et déclenche leur chiffrement, dans une architecture Zero Trust : chaque accès est authentifié, autorisé par rôle, tracé et surveillé.**

Quand un médecin saisit un dossier, un classifieur hybride (règles et modèle d'apprentissage supervisé) estime la sensibilité de chaque champ, et le diagnostic, les médicaments et les notes jugés sensibles sont chiffrés automatiquement. Autour de ce classifieur, l'application authentifie, autorise par rôle, trace et surveille chaque accès. Le modèle atteint une exactitude (accuracy) de 82,5 % sur 40 textes de test, mesurée sur un petit corpus de 197 phrases fictives : c'est un ordre de grandeur, pas une garantie, et les règles déterministes restent prioritaires.

**Données 100 % fictives.** Patients, dossiers et numéros NIR sont générés avec Faker ; aucune donnée de santé réelle n'est utilisée. Ce dépôt est une démonstration, pas un logiciel prêt pour la production (voir [Limites](#limites)).

## Ce que fait le projet

- **Classifie la sensibilité de chaque dossier** (faible, moyenne ou élevée) en combinant des règles déterministes, un modèle TF-IDF + Random Forest et une décision prudente : une seule règle déclenchée suffit à classer tout le dossier en sensibilité élevée.
- **Chiffre automatiquement** le diagnostic, les médicaments et les notes classés sensibles, avec Fernet (AES-128-CBC + HMAC-SHA256). La clé est lue depuis `.env` et n'est jamais versionnée.
- **Authentifie** avec des mots de passe hachés par bcrypt (12 caractères minimum, majuscule, minuscule, chiffre et caractère spécial), un changement de mot de passe imposé à la première connexion et une double authentification TOTP. Un appareil de confiance peut être dispensé de la 2FA pendant 30 jours ; le mot de passe reste toujours exigé.
- **Limite les tentatives** à 10 requêtes par minute sur la connexion, la 2FA et l'enregistrement d'un appareil.
- **Contrôle les accès** par rôle (admin, médecin, infirmier, patient) : un patient ne peut lire que son propre dossier, quel que soit l'identifiant demandé.
- **Trace** chaque action, accordée ou refusée, dans un journal d'audit horodaté.
- **Détecte quatre types d'attaque** sur une fenêtre glissante de 5 minutes et bloque les comptes visés, y compris un compte administrateur.
- **Calcule un score de conformité sur 100**, pondéré et recalculé à chaque appel par des requêtes SQL d'agrégation sur PostgreSQL.
- **Affiche un tableau de bord** (Chart.js) cloisonné selon le rôle, en français ou en anglais, en mode clair ou sombre. Les données venant du serveur sont échappées avant insertion dans la page.

## Couverture

Chaque ligne a été vérifiée dans le code et dans `data/model.pkl`, pas dans ce README.

| Fonctionnalité | Statut | Preuve |
|---|---|---|
| Classification hybride en 3 couches : règles, modèle, décision | couvert | `src/classifier.py` (`layer1_check`, `layer2_predict`, `layer3_decide`), `tests/test_classifier.py` |
| Modèle TF-IDF + Random Forest de 300 arbres | couvert | `src/train_model.py` (`train_and_save`) ; `data/model.pkl` (`n_estimators=300`, `accuracy=0.825`) |
| Chiffrement automatique des données sensibles | couvert | Les trois champs (diagnostic, médicaments, notes) sont chiffrés quand ils sont classés sensibles (`src/encryption.py`, `database.update_dossier_encrypted`, `database.update_entree_encrypted`) ; les notes déjà en base sont migrées au démarrage (`app.chiffrer_notes_existantes`). Tests : `tests/test_encryption.py`, `tests/test_ameliorations.py` (note relue chiffrée en base). |
| Mots de passe bcrypt, changement imposé, 2FA TOTP | couvert | `src/auth.py`, `src/app.py` |
| Appareil de confiance (30 jours, mot de passe toujours exigé) | couvert | `src/trusted_device.py` |
| Limitation des tentatives | couvert | `src/app.py` (`@limiter.limit("10 per minute")` sur 3 routes) |
| Contrôle d'accès par rôle | couvert | `src/rbac.py` (`check_access`) |
| Journal d'audit | couvert | `src/audit_log.py` (`log_access`) |
| Détection d'intrusion sur 4 vecteurs et blocage | couvert | `src/security_monitor.py` (`detecter_brute_force`, `detecter_password_spray`, `detecter_escalade_privileges`, `detecter_acces_anormal`, `scan_complet`) |
| Score de conformité pondéré | couvert | `src/app.py` (`calculer_conformite`) |
| Tableau de bord | couvert | `templates/index.html` (graphiques Chart.js, message de repli si la bibliothèque ne se charge pas) |
| Rapport PDF de conformité | couvert | `src/app.py` (`rapport_pdf`, réservé aux sessions authentifiées), `tests/test_ameliorations.py` (PDF renvoyé à un admin connecté, redirection sans session) |
| Interface bilingue FR / EN | couvert | `translations/` (Flask-Babel), `static/i18n.js` |
| Thème clair / sombre | couvert | `static/theme.js` (choix mémorisé, sinon préférence du système) |
| Échappement des données affichées (protection XSS) | couvert | `static/ui.js` (`esc`) |
| Tests automatisés | partiel | 31 tests (`tests/`), tous réussis en local ; aucune intégration continue. |
| Message de connexion unique (anti-énumération) | couvert | `src/app.py` (`api_login`) : « Identifiant ou mot de passe incorrect. » dans tous les cas, le motif réel restant dans le journal d'audit ; `tests/test_ameliorations.py` |

### Prochaines étapes

Évolutions prévues :

- chiffrer un dossier avant son enregistrement plutôt que juste après ;
- ajouter une intégration continue qui lance les tests à chaque push.

## Résultats clés

- Exactitude (accuracy) du modèle : 82,5 % sur 40 textes de test (`data/model.pkl`, clé `accuracy`). Limite : un seul découpage stratifié (20 % du corpus, `random_state=42`) d'un corpus de 197 phrases fictives rédigées pour le projet (98 sensibles, 99 non sensibles, `src/train_model.py`). Ce n'est pas une précision au sens ML, et aucun rappel n'est mesuré.
- Données de démonstration : 66 comptes (1 administrateur, 6 médecins, 9 infirmiers, 50 patients avec leur dossier), générés par `src/data_generator.py`. Limite : données entièrement fictives.
- Score de conformité : chiffrement 30 %, traçabilité 30 %, contrôle d'accès 20 %, complétude 20 % (`src/app.py`, `calculer_conformite`). Limite : il mesure l'état de la base de démonstration, pas une certification RGPD ou HDS.

## Démonstration

La vidéo de démonstration est accessible par le bouton en haut de cette page.

<!-- Emplacement des captures d'écran : déposer les images dans assets/, puis retirer ce commentaire.
<p align="center">
  <img src="assets/capture-clair.png" alt="Tableau de bord TCIM en mode clair" width="49%">
  <img src="assets/capture-sombre.png" alt="Tableau de bord TCIM en mode sombre" width="49%">
</p>
-->

## Comment ça marche

1. **Saisie** : un médecin crée ou modifie un dossier depuis le tableau de bord (`src/app.py`).
2. **Couche 1, règles** (`classifier.layer1_check`) : expressions régulières (NIR, dates, e-mails, téléphones, noms de praticiens) et mots-clés médicaux critiques en français et en anglais (`data/keywords_medicaux.txt`).
3. **Couche 2, modèle** (`classifier.layer2_predict`) : vectorisation TF-IDF (mots et bigrammes) et Random Forest de 300 arbres à classes équilibrées, entraîné une fois hors ligne (`src/train_model.py`) et chargé depuis `data/model.pkl`. Le modèle n'est utilisé qu'en français ; en anglais, seules les règles s'appliquent.
4. **Couche 3, décision** (`classifier.layer3_decide`) : une règle déclenchée donne une sensibilité élevée, prioritaire sur le modèle. Sinon, une probabilité d'au moins 0,7 donne une sensibilité élevée, d'au moins 0,5 une sensibilité moyenne, et en dessous une sensibilité faible.
5. **Chiffrement** (`src/encryption.py`) : le diagnostic, les médicaments et les notes classés sensibles sont chiffrés avec Fernet puis réécrits en base (`database.update_dossier_encrypted`). Un champ non sensible reste en clair et s'affiche tel quel. Au démarrage, les dossiers sensibles encore en clair sont chiffrés, ainsi que les notes sensibles enregistrées avant leur prise en charge.
6. **Contrôle d'accès et traçabilité** : chaque requête passe par `rbac.check_access`, et le résultat est écrit dans le journal d'audit (`audit_log.log_access`).
7. **Surveillance** (`src/security_monitor.py`) : le journal est analysé sur les 5 dernières minutes.

| Menace | Seuil | Gravité | Réaction |
|---|---|---|---|
| Force brute (connexion ou 2FA) | 3 échecs | critique | alerte et blocage du compte |
| Password spray | 3 comptes visés | critique | alerte et blocage des comptes visés |
| Escalade de privilèges (compte patient) | 2 actions non autorisées | critique | alerte et blocage du compte |
| Volume d'accès anormal | 10 actions | élevé | alerte |

Un administrateur débloque un compte depuis l'interface en confirmant son mot de passe, en choisissant une catégorie et en écrivant un motif ; le déblocage est tracé. Si tous les administrateurs sont bloqués, `deblocage_secours.py` permet un déblocage hors ligne, réservé à une personne qui a un accès direct au serveur, et trace lui aussi l'action.

## Limites

- **Petit corpus d'entraînement** : 197 phrases fictives en français, et une exactitude mesurée sur 40 textes seulement. C'est pour cela que les règles déterministes restent prioritaires.
- **Chiffrement après enregistrement** : un dossier est d'abord enregistré, puis chiffré juste après sa classification.
- **Serveur de développement Flask** (`debug=True`, écoute sur toutes les interfaces) : à utiliser en local uniquement. Un déploiement réel demanderait un serveur WSGI, HTTPS et `debug` désactivé.
- **Comptes de démonstration** aux mots de passe publics (voir plus bas).
- **Une seule clé** : la même `SECRET_KEY` sert au chiffrement Fernet et à la signature des sessions. En production, il faudrait deux clés distinctes, gérées par un coffre de secrets.
- **Limitation des tentatives en mémoire** : les compteurs repartent de zéro au redémarrage et ne sont pas partagés entre plusieurs processus.
- **Énumération des identifiants, cas restants** : le message d'échec est le même pour un compte inexistant et un mauvais mot de passe, mais un compte bloqué est signalé comme tel, et la réponse est plus lente quand le compte existe (le mot de passe n'est vérifié par bcrypt que dans ce cas).
- **Modèle chargé avec `pickle`** : ne remplacer `data/model.pkl` que par un fichier de confiance, ou le régénérer avec `python src/train_model.py`.

## Lancer le projet

Prérequis : Python 3 et un serveur PostgreSQL accessible. Toutes les commandes se lancent depuis la racine du dépôt.

    git clone https://github.com/Kadi2207/ai-health-data-security.git
    cd ai-health-data-security
    python -m venv venv
    venv\Scripts\activate            # Windows ; sous Mac ou Linux : source venv/bin/activate
    pip install -r requirements.txt

Configuration : copier `.env.example` en `.env`, puis y coller une clé générée par la commande ci-dessous à la place de `your_secret_key_here`, et renseigner `PG_HOST`, `PG_PORT`, `PG_DATABASE`, `PG_USER` et `PG_PASSWORD`.

    python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

Base de données, comptes et application :

    createdb -U postgres tcim_medical
    python src/data_generator.py     # réinitialise entièrement la base et crée les 66 comptes
    python src/init_auth.py          # attribue les mots de passe initiaux, écrit comptes_acces.txt
    python src/app.py                # http://localhost:5000

`comptes_acces.txt` contient des mots de passe en clair : il est exclu de Git et ne doit pas être partagé.

### Comptes de démonstration

**Ces comptes servent uniquement à la démonstration, sur des données fictives.** Leurs mots de passe sont publics, puisqu'ils sont écrits dans `src/init_auth.py`. L'application impose de les changer à la première connexion, et ils ne doivent jamais être utilisés tels quels sur un déploiement réel.

| Identifiant | Rôle | Mot de passe initial |
|---|---|---|
| `admin1` | Administrateur | `Admin@TCIM2026` |
| `medecin1` | Médecin | `Medecin@TCIM2026` |
| `infirmier1` | Infirmier | `Infirmier@TCIM26` |
| `patient1` | Patient | `Patient@TCIM2026` |

Les autres comptes reçoivent le mot de passe initial commun défini dans `src/init_auth.py` (`MDP_DEFAUT`). À la première connexion : mot de passe initial, nouveau mot de passe, scan du QR code dans une application d'authentification, puis code à 6 chiffres.

### Démonstration d'attaque

Pendant que l'application tourne, dans un second terminal :

    python attaque.py                # force brute, password spray, escalade de privilèges et volume anormal en parallèle
    python verif.py                  # menaces détectées dans la fenêtre courante, puis scan

Le tableau de bord affiche les alertes et les blocages en temps réel.

### Tests

    pip install pytest
    python -m pytest tests

Résultat au 2026-11-27, en local : 31 tests réussis sur 31 (classification, chiffrement, chiffrement des notes en base, affichage d'un dossier dont un seul champ est chiffré, export PDF, message de connexion). Les tests demandent une `SECRET_KEY` valide dans `.env`. Ceux de `tests/test_ameliorations.py` créent une base PostgreSQL temporaire, puis la suppriment ; la base de l'application n'est jamais touchée, et sans serveur PostgreSQL joignable ces tests sont ignorés. Aucune intégration continue ne les relance pour l'instant.

### Traductions

Après une modification des textes de l'interface :

    pybabel extract -F babel.cfg -o messages.pot .
    pybabel update -i messages.pot -d translations
    pybabel compile -d translations

## Structure du dépôt

    src/app.py                  application Flask : routes, sessions, limitation des tentatives, score de conformité
    src/classifier.py           classification de la sensibilité en 3 couches
    src/train_model.py          corpus d'entraînement et entraînement du modèle (génère data/model.pkl)
    src/encryption.py           chiffrement Fernet
    src/auth.py                 bcrypt, TOTP, QR code
    src/trusted_device.py       appareils de confiance
    src/rbac.py                 contrôle d'accès par rôle
    src/audit_log.py            journal d'audit
    src/security_monitor.py     détection d'intrusion et blocage automatique
    src/main_pipeline.py        pipeline complet en ligne de commande
    src/database.py             accès PostgreSQL
    src/data_generator.py       génération des données fictives
    src/init_auth.py            initialisation des comptes de démonstration
    templates/                  pages HTML (Jinja2)
    static/                     CSS et JavaScript (thème, traduction, interface)
    translations/               catalogues FR et EN
    data/                       schémas SQL, mots-clés médicaux, modèle entraîné (model.pkl)
    tests/                      tests de la classification, du chiffrement, de l'export PDF et de la connexion
    attaque.py                  démonstration d'attaque multi-vecteurs
    verif.py                    diagnostic du moteur de détection
    deblocage_secours.py        déblocage de secours hors ligne

## Stack

| Composant | Technologie |
|---|---|
| Langage | Python 3 |
| Application web | Flask, Flask-Babel, Flask-Limiter |
| Base de données | PostgreSQL (psycopg2) |
| Classification | scikit-learn (TF-IDF, Random Forest), pandas, règles et mots-clés |
| Chiffrement | cryptography (Fernet : AES-128-CBC + HMAC-SHA256) |
| Authentification | bcrypt, pyotp (TOTP), qrcode |
| Données fictives | Faker |
| Rapport PDF | reportlab |
| Tableau de bord | Chart.js |
| Tests | pytest |

## Licence

Tous droits réservés, consultation autorisée pour évaluation uniquement (voir [LICENSE](LICENSE)). Toute autre utilisation, copie, modification ou redistribution demande l'autorisation écrite préalable de l'autrice.

## Autrice

**Kadidiatou Ibrahima Bagayoko**. [LinkedIn](https://linkedin.com/in/kadi-bagayoko), [portfolio](https://kadidiatou-bagayoko.vercel.app/), kadibaga22@gmail.com
