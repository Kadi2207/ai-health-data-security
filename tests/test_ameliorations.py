"""Tests des trois améliorations : chiffrement du champ notes, export PDF du
rapport de conformité, message de connexion unique (anti-énumération).

Ils tournent sur une base PostgreSQL TEMPORAIRE, créée puis supprimée par le
test : la base de l'application n'est jamais lue ni modifiée. Sans serveur
PostgreSQL joignable (paramètres PG_* du fichier .env), ces tests sont ignorés.
"""
import os
import sys
import uuid

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from dotenv import load_dotenv
load_dotenv()

import psycopg2
import database

RACINE = os.path.join(os.path.dirname(__file__), "..")
MESSAGE_GENERIQUE_FR = "Identifiant ou mot de passe incorrect."
MESSAGE_GENERIQUE_EN = "Incorrect username or password."


# ── Base temporaire ───────────────────────────────────────────────────────────
def _connexion_maintenance():
    conn = psycopg2.connect(host=database.PG_HOST, port=database.PG_PORT, dbname="postgres",
                            user=database.PG_USER, password=database.PG_PASSWORD)
    conn.autocommit = True
    return conn


@pytest.fixture(scope="module")
def base_temporaire():
    try:
        maintenance = _connexion_maintenance()
    except psycopg2.OperationalError:
        pytest.skip("PostgreSQL injoignable : tests d'intégration ignorés")
    nom = f"tcim_test_{uuid.uuid4().hex[:10]}"
    with maintenance.cursor() as cur:
        cur.execute(f'CREATE DATABASE "{nom}"')
    base_application = database.PG_DATABASE
    database.PG_DATABASE = nom
    try:
        conn = database.get_connection()
        with open(os.path.join(RACINE, "data", "schema_postgresql.sql"), encoding="utf-8") as f:
            conn.cursor().execute(f.read())
        conn.commit()
        conn.close()
        yield nom
    finally:
        database.PG_DATABASE = base_application
        with maintenance.cursor() as cur:
            cur.execute(f'DROP DATABASE IF EXISTS "{nom}" WITH (FORCE)')
        maintenance.close()


@pytest.fixture(scope="module")
def appli(base_temporaire):
    import app as module_app
    import trusted_device
    from audit_log import init_audit_tables
    init_audit_tables()
    trusted_device.init_table()
    module_app.app.config["TESTING"] = True
    return module_app


@pytest.fixture
def client(appli):
    return appli.app.test_client()


def _ouvrir_session(client, appli, username, role, lang=None):
    """Session identique à celle posée après une 2FA réussie (boot_id compris) :
    login_required n'est ni contourné ni modifié."""
    with client.session_transaction() as s:
        s.clear()
        s.update(authenticated=True, boot_id=appli.SERVER_BOOT_ID, username=username, role=role)
        if lang:
            s["lang"] = lang


def _ligne(sql, params=()):
    conn = database.get_connection()
    cur = conn.cursor()
    cur.execute(sql, params)
    ligne = cur.fetchone()
    conn.close()
    return ligne


def _executer(sql, params=()):
    conn = database.get_connection()
    cur = conn.cursor()
    cur.execute(sql, params)
    ligne = cur.fetchone() if cur.description else None
    conn.commit()
    conn.close()
    return ligne


NOTE_SENSIBLE = "Suivi psychiatrique mensuel, traitement neuroleptique"
NOTE_BANALE = "Rendez-vous de contrôle dans 6 mois"


def _note_est_sensible(note):
    from classifier import classify_dossier
    return "notes" in classify_dossier({"notes": note})["sensitive_fields"]


# ── 1. Chiffrement du champ notes ─────────────────────────────────────────────
def test_classifieur_juge_les_notes_de_test_comme_attendu():
    assert _note_est_sensible(NOTE_SENSIBLE)
    assert not _note_est_sensible(NOTE_BANALE)


def _creer_dossier(client, appli, notes):
    _ouvrir_session(client, appli, "medecin_test", "medecin")
    rep = client.post("/api/creer-dossier", json={
        "nom": "Test", "prenom": "Patient", "date_naissance": "01/01/1980", "nir": "180017500000000",
        "diagnostic": "Patient séropositif VIH sous traitement",
        "medicaments": "Ténofovir 300mg",
        "notes": notes,
    })
    assert rep.status_code == 200 and rep.get_json()["success"]
    return rep.get_json()


def test_note_sensible_chiffree_en_base_et_lisible_a_l_affichage(client, appli):
    from encryption import decrypt
    data = _creer_dossier(client, appli, NOTE_SENSIBLE)

    en_base = _ligne("SELECT diagnostic, notes, is_encrypted FROM dossiers_medicaux WHERE id = %s",
                     (data["dossier_id"],))
    assert en_base["is_encrypted"] == 1
    assert en_base["notes"] != NOTE_SENSIBLE
    assert en_base["notes"].startswith("gAAAAA")
    assert decrypt(en_base["notes"]) == NOTE_SENSIBLE
    assert en_base["diagnostic"].startswith("gAAAAA")

    rep = client.get(f"/api/historique/{data['patient_id']}")
    assert rep.get_json()["entrees"][0]["notes"] == NOTE_SENSIBLE


def test_note_non_sensible_reste_en_clair_et_s_affiche(client, appli):
    data = _creer_dossier(client, appli, NOTE_BANALE)
    en_base = _ligne("SELECT notes, is_encrypted FROM dossiers_medicaux WHERE id = %s",
                     (data["dossier_id"],))
    assert en_base["is_encrypted"] == 1
    assert en_base["notes"] == NOTE_BANALE

    rep = client.get(f"/api/historique/{data['patient_id']}")
    assert rep.get_json()["entrees"][0]["notes"] == NOTE_BANALE


def test_note_sensible_d_une_entree_ajoutee_chiffree_en_base(client, appli):
    from encryption import decrypt
    data = _creer_dossier(client, appli, NOTE_BANALE)
    rep = client.post("/api/ajouter-entree", json={
        "patient_id": data["patient_id"],
        "diagnostic": "Dépression sévère, hospitalisation",
        "medicaments": "Sertraline 50mg",
        "notes": NOTE_SENSIBLE,
    })
    assert rep.get_json()["success"]

    en_base = _ligne("SELECT notes FROM entrees_dossier WHERE id = %s", (rep.get_json()["entree_id"],))
    assert en_base["notes"].startswith("gAAAAA")
    assert decrypt(en_base["notes"]) == NOTE_SENSIBLE

    historique = client.get(f"/api/historique/{data['patient_id']}").get_json()["entrees"]
    assert NOTE_SENSIBLE in [e["notes"] for e in historique]


def test_migration_chiffre_les_notes_sensibles_restees_en_clair(appli):
    from encryption import decrypt
    patient = _executer("INSERT INTO patients (nom, prenom, date_naissance, nir) "
                        "VALUES ('Ancien', 'Dossier', '01/01/1970', '170017500000000') RETURNING id")
    sensible = _executer("INSERT INTO dossiers_medicaux (patient_id, diagnostic, medicaments, notes, is_encrypted) "
                         "VALUES (%s, 'gAAAAAdiag', 'gAAAAAmed', %s, 1) RETURNING id",
                         (patient["id"], NOTE_SENSIBLE))
    banale = _executer("INSERT INTO dossiers_medicaux (patient_id, diagnostic, medicaments, notes, is_encrypted) "
                       "VALUES (%s, 'gAAAAAdiag', 'gAAAAAmed', %s, 1) RETURNING id",
                       (patient["id"], NOTE_BANALE))

    appli.chiffrer_notes_existantes()
    premier = _ligne("SELECT notes FROM dossiers_medicaux WHERE id = %s", (sensible["id"],))["notes"]
    assert decrypt(premier) == NOTE_SENSIBLE
    assert _ligne("SELECT notes FROM dossiers_medicaux WHERE id = %s", (banale["id"],))["notes"] == NOTE_BANALE

    # Relancer la migration ne rechiffre pas une note déjà chiffrée
    appli.chiffrer_notes_existantes()
    assert _ligne("SELECT notes FROM dossiers_medicaux WHERE id = %s", (sensible["id"],))["notes"] == premier


# ── 2. Export PDF du rapport de conformité ────────────────────────────────────
def test_rapport_pdf_renvoie_un_pdf_pour_un_admin_connecte(client, appli):
    _ouvrir_session(client, appli, "admin_test", "admin")
    rep = client.get("/rapport-pdf")
    assert rep.status_code == 200
    assert rep.mimetype == "application/pdf"
    assert rep.data.startswith(b"%PDF")


def test_rapport_pdf_reste_protege_sans_session(client):
    rep = client.get("/rapport-pdf")
    assert rep.status_code == 302
    assert "/login" in rep.headers["Location"]


# ── 3. Message de connexion unique ────────────────────────────────────────────
@pytest.fixture
def compte_existant(appli):
    from auth import set_user_credentials
    username = f"compte_{uuid.uuid4().hex[:6]}"
    database.insert_utilisateur("Test", "Compte", "infirmier", username)
    set_user_credentials(username, "MotDePasse@Valide2026")
    return username


def _echec_connexion(client, username, password):
    rep = client.post("/api/login", json={"username": username, "password": password})
    data = rep.get_json()
    assert data["success"] is False
    return data


def test_meme_message_que_le_compte_existe_ou_non(client, compte_existant):
    inconnu = f"inconnu_{uuid.uuid4().hex[:6]}"
    rep_inconnu = _echec_connexion(client, inconnu, "peu importe")
    rep_existant = _echec_connexion(client, compte_existant, "mauvais mot de passe")
    assert rep_inconnu == rep_existant == {"success": False, "reason": MESSAGE_GENERIQUE_FR}


def test_message_unique_traduit_en_anglais(client, appli, compte_existant):
    with client.session_transaction() as s:
        s["lang"] = "en"
    assert _echec_connexion(client, f"inconnu_{uuid.uuid4().hex[:6]}", "x")["reason"] == MESSAGE_GENERIQUE_EN
    assert _echec_connexion(client, compte_existant, "mauvais")["reason"] == MESSAGE_GENERIQUE_EN


def test_le_journal_garde_le_motif_reel(client, compte_existant):
    inconnu = f"inconnu_{uuid.uuid4().hex[:6]}"
    _echec_connexion(client, inconnu, "x")
    _echec_connexion(client, compte_existant, "mauvais")

    def derniere_action(username):
        return _ligne("SELECT action, resultat FROM audit_logs WHERE utilisateur_id = %s "
                      "ORDER BY id DESC LIMIT 1", (username,))

    assert dict(derniere_action(inconnu)) == {
        "action": "Échec connexion — utilisateur introuvable", "resultat": "refusé"}
    assert dict(derniere_action(compte_existant)) == {
        "action": "Échec connexion — mot de passe incorrect", "resultat": "refusé"}


def test_les_echecs_restent_comptes_par_la_detection_de_force_brute(client, compte_existant):
    from security_monitor import detecter_brute_force
    for _ in range(3):
        _echec_connexion(client, compte_existant, "mauvais")
    conn = database.get_connection()
    try:
        cibles = [m["utilisateur"] for m in detecter_brute_force(conn)]
    finally:
        conn.close()
    assert compte_existant in cibles
