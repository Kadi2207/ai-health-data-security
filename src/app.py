import os
from functools import wraps
from flask import (
    Flask, render_template, request, jsonify,
    send_file, session, redirect, url_for
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv

load_dotenv()
from flask_babel import Babel, gettext as _

from database import (
    get_all_patients, get_utilisateur_by_username, init_db,
    get_stats_sensitivity, get_stats_access_by_role, get_stats_counters, get_doit_changer_mdp, set_password_and_clear_flag, get_connection
   
)
from main_pipeline import process_dossier
from audit_log import (
    get_all_logs, get_all_alertes, log_access, init_audit_tables
)
from auth import (
    authenticate, verify_otp, get_user_auth,
    get_totp_uri, generate_qr_code
)
from security_monitor import scan_complet, compte_est_bloque
import trusted_device

app = Flask(__name__, template_folder="../templates", static_folder="../static")
app.secret_key = os.getenv("SECRET_KEY", "dev-secret-key-change-me")
limiter = Limiter(get_remote_address, app=app, default_limits=["200 per hour"])
# ── Configuration de l'internationalisation (bilingue FR / EN) ────────────────
app.config["BABEL_DEFAULT_LOCALE"] = "fr"
app.config["BABEL_SUPPORTED_LOCALES"] = ["fr", "en"]
# Le dossier translations est à la racine du projet (un niveau au-dessus de src/)
app.config["BABEL_TRANSLATION_DIRECTORIES"] = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "translations"
)

def get_locale():
    # 1. Si l'utilisateur a explicitement choisi une langue (stockée en session), on la respecte
    lang = session.get("lang")
    if lang in app.config["BABEL_SUPPORTED_LOCALES"]:
        return lang
    # 2. Sinon, on prend la langue par défaut (français)
    return app.config["BABEL_DEFAULT_LOCALE"]

babel = Babel()
babel.init_app(app, locale_selector=get_locale)

# Rendre la langue courante accessible dans tous les templates
@app.context_processor
def inject_locale():
    return {"current_lang": get_locale()}
import secrets
from datetime import timedelta

# Identifiant unique généré à CHAQUE démarrage du serveur.
# Sert à invalider les sessions ouvertes avant un redémarrage.
SERVER_BOOT_ID = secrets.token_hex(8)

# La session expire à la fermeture du navigateur (non permanente).
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=8)

# ── Décorateur : protéger les routes ─────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # Session absente OU issue d'un démarrage précédent du serveur → ré-authentification
        if not session.get("authenticated") or session.get("boot_id") != SERVER_BOOT_ID:
            session.clear()
            return redirect(url_for("login_page"))
        return f(*args, **kwargs)
    return decorated


# ── Pages d'authentification ─────────────────────────────────────────────────
@app.route("/login")
def login_page():
    return render_template("login.html")


@app.route("/setup-2fa")
def setup_2fa_page():
    return render_template("setup_2fa.html")


@app.route("/logout")
def logout():
    # La préférence de langue (pur affichage) survit à la déconnexion
    lang = session.get("lang")
    session.clear()
    if lang:
        session["lang"] = lang
    return redirect(url_for("login_page"))

@app.route("/set-lang/<lang>")
def set_lang(lang):
    """Change la langue de l'interface (fr ou en) et revient à la page précédente."""
    if lang in app.config["BABEL_SUPPORTED_LOCALES"]:
        session["lang"] = lang
    # Revenir à la page d'où vient l'utilisateur, uniquement si elle est sur ce
    # même site (évite une redirection ouverte vers un domaine externe)
    retour = request.referrer
    if retour:
        from urllib.parse import urlparse
        cible = urlparse(retour)
        if cible.netloc == request.host and cible.scheme in ("http", "https"):
            return redirect(retour)
    return redirect(url_for("index"))

@app.route("/change-password")
def change_password_page():
    # Accessible seulement si une authentification mot de passe a réussi
    if not session.get("pending_user") and not session.get("authenticated"):
        return redirect(url_for("login_page"))
    return render_template("change_password.html")


@app.route("/api/change-password", methods=["POST"])
def api_change_password():
    from auth import hash_password
    import re

    # L'utilisateur concerné : soit en attente (première connexion), soit déjà connecté
    username = session.get("pending_user") or session.get("username")
    if not username:
        return jsonify({"success": False, "reason": _("Session invalide.")}), 403
    
    data = request.get_json()
    new_password = data.get("new_password", "")

    # Validation stricte côté serveur (jamais se fier au navigateur seul)
    if (len(new_password) < 12
            or not re.search(r"[A-Z]", new_password)
            or not re.search(r"[a-z]", new_password)
            or not re.search(r"[0-9]", new_password)
            or not re.search(r"[^A-Za-z0-9]", new_password)):
        return jsonify({"success": False, "reason": _("Le mot de passe ne respecte pas la politique de sécurité.")})
    
    set_password_and_clear_flag(username, hash_password(new_password))
    log_access(username, "Changement de mot de passe (première connexion)",
               ressource="Compte utilisateur", resultat="accordé")

    return jsonify({"success": True})

# ── API d'authentification ────────────────────────────────────────────────────
# Motifs d'échec renvoyés par auth.authenticate() (inchangé) -> libellé d'audit.
# La distinction reste DANS LE JOURNAL pour le suivi interne. Chaque libellé
# contient « connexion » : les règles de force brute et de password spray
# (security_monitor) continuent de compter ces échecs.
_AUDIT_ECHEC_CONNEXION = {
    "Utilisateur introuvable": "Échec connexion — utilisateur introuvable",
    "Mot de passe incorrect": "Échec connexion — mot de passe incorrect",
}


@app.route("/api/login", methods=["POST"])
@limiter.limit("10 per minute")
def api_login():
    data = request.get_json()
    username = data.get("username")

    # Vérifier si le compte est bloqué pour raison de sécurité
    if compte_est_bloque(username):
        log_access(username, "Tentative connexion sur compte bloqué", resultat="refusé")
        return jsonify({
            "success": False,
            "reason": _("Compte bloqué pour raison de sécurité. Contactez l'administrateur.")
        })

    result = authenticate(username, data.get("password"))
    motif_interne = None
    if not result["success"]:
        # Anti-énumération : l'utilisateur voit toujours le même message, que
        # le compte existe ou non. Le motif réel est gardé pour le journal.
        motif_interne = result.get("reason")
        result = {"success": False, "reason": _("Identifiant ou mot de passe incorrect.")}
    statut_appareil = trusted_device.ABSENT
    if result["success"]:
        session["pending_user"] = result["username"]
        session["pending_role"] = result["role"]
        log_access(username, "Connexion — mot de passe validé", ressource="Accès au système", resultat="accordé")

        # Lot 5 : le mot de passe vient d'être vérifié. Si l'appareil est un
        # appareil de confiance valide POUR CE COMPTE, la 2FA n'est pas demandée.
        # Dans tous les autres cas, on continue vers la 2FA (chemin par défaut).
        statut_appareil = _statut_appareil_confiance(result["username"])
        if statut_appareil == trusted_device.VALIDE:
            return _connexion_par_appareil_confiance(result["username"], result["role"])
    else:
        # Log de l'échec — permet la détection de force brute
        log_access(username,
                   _AUDIT_ECHEC_CONNEXION.get(motif_interne, "Échec connexion — mot de passe incorrect"),
                   resultat="refusé")

    reponse = jsonify(result)
    if statut_appareil in _STATUTS_COOKIE_A_EFFACER:
        # Cookie inutilisable : on l'efface pour ne pas le retracer à chaque connexion
        reponse.delete_cookie(trusted_device.NOM_COOKIE, path=trusted_device.CHEMIN_COOKIE)
    return reponse


# ── Appareil de confiance (lot 5) ─────────────────────────────────────────────
# Libellés d'audit : volontairement SANS les mots « connexion », « 2FA »,
# « login », « delete », « write », « manage », « forçage », « RBAC » quand le
# résultat est « refusé », pour ne pas fausser les règles de détection
# d'intrusion (security_monitor) qui s'appuient sur ces mots.
_AUDIT_APPAREIL = {
    trusted_device.INVALIDE: "Appareil de confiance : cookie falsifié ou invalide — double authentification exigée",
    trusted_device.INCONNU: "Appareil de confiance non reconnu — double authentification exigée",
    trusted_device.EXPIRE: "Appareil de confiance expiré — double authentification exigée",
    trusted_device.REVOQUE: "Appareil de confiance révoqué — double authentification exigée",
}
_STATUTS_COOKIE_A_EFFACER = set(_AUDIT_APPAREIL)


def _statut_appareil_confiance(username):
    """Vérifie le cookie d'appareil de confiance pour un compte dont le mot de
    passe vient d'être validé, et trace dans l'audit tout cookie refusé."""
    statut = trusted_device.verifier(
        request.cookies.get(trusted_device.NOM_COOKIE), username, app.secret_key
    )
    if statut in _AUDIT_APPAREIL:
        log_access(username, _AUDIT_APPAREIL[statut],
                   ressource="Appareil de confiance", resultat="refusé")
    return statut


def _connexion_par_appareil_confiance(username, role):
    """Ouvre la session sans 2FA (mot de passe déjà vérifié, appareil reconnu).
    Champs de session identiques à ceux posés par /api/verify-2fa (inchangée),
    plus un marqueur : une session ouverte ainsi ne peut PAS enregistrer un
    nouvel appareil de confiance (sinon la confiance se prolongerait sans
    jamais repasser par la 2FA)."""
    session["authenticated"] = True
    session["boot_id"] = SERVER_BOOT_ID
    session["username"] = username
    session["role"] = role
    session["auth_method"] = "appareil_confiance"
    log_access(username, "Connexion — appareil de confiance (double authentification non demandée)",
               ressource="Accès au système", resultat="accordé")

    # Première connexion : même règle que la 2FA, mot de passe à changer d'abord
    destination = "/change-password" if get_doit_changer_mdp(username) else "/"
    return jsonify({"success": True, "trusted_device": True, "redirect": destination})


@app.route("/api/appareil-confiance", methods=["POST"])
@limiter.limit("10 per minute")
@login_required
def api_appareil_confiance():
    """Enregistre le navigateur courant comme appareil de confiance (30 jours).
    Appelée par la page de connexion juste après une 2FA réussie, uniquement si
    l'utilisateur a coché la case (non cochée par défaut)."""
    username = session.get("username")

    if session.get("auth_method") == "appareil_confiance":
        log_access(username,
                   "Enregistrement d'appareil de confiance refusé (session ouverte sans double authentification)",
                   ressource="Appareil de confiance", resultat="refusé")
        return jsonify({"success": False,
                        "reason": _("La double authentification est requise pour faire confiance à cet appareil.")}), 403

    valeur, expiration = trusted_device.creer(
        username, app.secret_key, request.headers.get("User-Agent", "")
    )
    log_access(username, f"Appareil de confiance enregistré ({trusted_device.DUREE_JOURS} jours)",
               ressource=f"Appareil de confiance · expire le {expiration.strftime('%Y-%m-%d %H:%M')}",
               resultat="accordé")

    reponse = jsonify({"success": True})
    reponse.set_cookie(
        trusted_device.NOM_COOKIE, valeur,
        max_age=trusted_device.DUREE_JOURS * 86400,
        path=trusted_device.CHEMIN_COOKIE,
        httponly=True,          # inaccessible au JavaScript
        samesite="Strict",      # jamais envoyé depuis un autre site
        secure=request.is_secure  # Secure dès que l'application est en HTTPS
    )
    return reponse


@app.route("/api/verify-2fa", methods=["POST"])
@limiter.limit("10 per minute")
def api_verify_2fa():
    data = request.get_json()
    username = data.get("username")
    code = data.get("code")

    # Le mot de passe doit avoir été validé juste avant, POUR CE COMPTE :
    # /api/login pose session["pending_user"] uniquement après un mot de passe correct.
    if not session.get("pending_user") or session.get("pending_user") != username:
        log_access(username, "Échec 2FA — mot de passe non validé au préalable", resultat="refusé")
        return jsonify({"success": False,
                        "reason": _("Session de connexion invalide. Veuillez ressaisir votre mot de passe.")})

    # Un compte bloqué est refusé AVANT toute vérification du code
    if compte_est_bloque(username):
        log_access(username, "Tentative 2FA sur compte bloqué", resultat="refusé")
        return jsonify({"success": False,
                        "reason": _("Compte bloqué pour raison de sécurité. Contactez l'administrateur.")})

    user = get_user_auth(username)
    if not user:
        return jsonify({"success": False, "reason": _("Utilisateur introuvable")})

    if verify_otp(user["otp_secret"], code):
        session["authenticated"] = True
        session["boot_id"] = SERVER_BOOT_ID
        session["username"] = username
        session["role"] = user["role"]
        log_access(username, "Connexion 2FA réussie", ressource="Accès au système", resultat="accordé")

        # Première connexion : mot de passe par défaut à changer avant tout accès
        if get_doit_changer_mdp(username):
            return jsonify({"success": True, "redirect": "/change-password"})

        return jsonify({"success": True, "redirect": "/"})
    else:
        log_access(username, "Échec connexion 2FA", resultat="refusé")
        return jsonify({"success": False, "reason": _("Code 2FA incorrect")})



@app.route("/api/qr-code/<username>")
def api_qr_code(username):
    user = get_user_auth(username)
    if not user or not user["otp_secret"]:
        return jsonify({"error": _("Utilisateur sans secret 2FA")}), 404
    uri = get_totp_uri(username, user["otp_secret"])
    qr = generate_qr_code(uri)
    return jsonify({"qr_code": qr, "secret": user["otp_secret"]})


# ── Application principale (protégée) ─────────────────────────────────────────
@app.route("/")
@login_required
def index():
    patients = get_all_patients()
    return render_template(
        "index.html",
        patients=[dict(p) for p in patients],
        current_user=session.get("username"),
        current_role=session.get("role")
    )


@app.route("/process", methods=["POST"])
@login_required
def process():
    data = request.get_json()
    patient_id = data.get("patient_id")
    username   = session.get("username")
    permission = data.get("permission", "read_dossier")

    if not patient_id:
        return jsonify({"erreur": _("patient_id requis")}), 400

    result = process_dossier(
        patient_id=int(patient_id),
        username=username,
        permission=permission
    )
    return jsonify(result)

# ── Création et gestion de dossiers (RÉSERVÉ AU MÉDECIN) ──────────────────────
@app.route("/api/creer-dossier", methods=["POST"])
@login_required
def api_creer_dossier():
    """Création d'un dossier médical par un médecin.
    Deux cas : patient existant (patient_id fourni) OU nouveau patient (infos patient fournies).
    Le dossier passe ensuite dans le pipeline : classification IA → chiffrement → stockage.
    """
    # Sécurité : seul le médecin peut créer un dossier
    if session.get("role") != "medecin":
        log_access(session.get("username"),
                   "Tentative de création de dossier",
                   ressource="Création dossier refusée (rôle non autorisé)",
                   resultat="refusé")
        return jsonify({"success": False, "reason": _("Seul un médecin peut créer un dossier.")}), 403

    from database import insert_patient, insert_dossier_complet, get_patient_id_of_user
    from classifier import classify_dossier
    from encryption import encrypt_dossier
    from database import update_dossier_encrypted

    data = request.get_json()
    medecin = session.get("username")

    diagnostic = (data.get("diagnostic") or "").strip()
    medicaments = (data.get("medicaments") or "").strip()
    notes = (data.get("notes") or "").strip()

    if not diagnostic:
        return jsonify({"success": False, "reason": _("Le diagnostic est obligatoire.")})

    # Déterminer le patient : existant ou nouveau
    patient_id = data.get("patient_id")

    if not patient_id:
        # Cas nouveau patient : on crée d'abord le patient
        nom = (data.get("nom") or "").strip()
        prenom = (data.get("prenom") or "").strip()
        date_naissance = (data.get("date_naissance") or "").strip()
        nir = (data.get("nir") or "").strip()
        adresse = (data.get("adresse") or "").strip()
        medecin_traitant = (data.get("medecin_traitant") or "").strip()

        if not nom or not prenom or not date_naissance:
            return jsonify({"success": False, "reason": _("Nom, prénom et date de naissance sont obligatoires pour un nouveau patient.")})

        patient_id = insert_patient(nom, prenom, date_naissance, nir, adresse, medecin_traitant)

    patient_id = int(patient_id)

    # Créer le dossier avec le médecin auteur
    dossier_id = insert_dossier_complet(patient_id, diagnostic, medicaments, notes, medecin_auteur=medecin)

    # PIPELINE : classification IA + chiffrement automatique si sensible
    dossier_dict = {"diagnostic": diagnostic, "medicaments": medicaments, "notes": notes}
    classification = classify_dossier(dossier_dict)
    sensitive_fields = classification["sensitive_fields"]
    if sensitive_fields:
        encrypted = encrypt_dossier(dossier_dict, sensitive_fields)
        update_dossier_encrypted(
            dossier_id=dossier_id,
            encrypted_diagnostic=encrypted.get("diagnostic", diagnostic),
            encrypted_medicaments=encrypted.get("medicaments", medicaments),
            sensitivity_level=classification["global_sensitivity"],
            encrypted_notes=encrypted.get("notes", notes)
        )

    log_access(medecin,
               f"Création d'un dossier médical (patient_id={patient_id})",
               ressource=f"Dossier #{dossier_id} — sensibilité : {classification['global_sensitivity']}",
               resultat="accordé")

    return jsonify({
        "success": True,
        "dossier_id": dossier_id,
        "patient_id": patient_id,
        "sensitivity": classification["global_sensitivity"],
        "chiffre": bool(sensitive_fields),
        "message": _("Dossier créé, classé et sécurisé avec succès.")
    })


@app.route("/api/patients-sans-dossier")
@login_required
def api_patients_sans_dossier():
    """Liste des patients sans dossier (pour le formulaire de création — médecin uniquement)."""
    if session.get("role") != "medecin":
        return jsonify({"success": False, "reason": _("Réservé au médecin.")}), 403
    from database import get_patients_sans_dossier
    patients = get_patients_sans_dossier()
    return jsonify([dict(p) for p in patients])

# ── Historique médical : ajouter une entrée / consulter (MÉDECIN) ─────────────
@app.route("/api/ajouter-entree", methods=["POST"])
@login_required
def api_ajouter_entree():
    """Le médecin ajoute une entrée à l'historique d'un patient.
    L'entrée est classée (IA) puis chiffrée si sensible. Les entrées
    précédentes ne sont JAMAIS modifiées (historique inaltérable).
    """
    if session.get("role") != "medecin":
        log_access(session.get("username"),
                   "Tentative d'ajout d'entrée médicale",
                   ressource="Ajout refusé (rôle non autorisé)",
                   resultat="refusé")
        return jsonify({"success": False, "reason": _("Seul un médecin peut ajouter une entrée.")}), 403

    from database import insert_entree, update_entree_encrypted
    from classifier import classify_dossier
    from encryption import encrypt_dossier

    data = request.get_json()
    medecin = session.get("username")
    patient_id = data.get("patient_id")
    diagnostic = (data.get("diagnostic") or "").strip()
    medicaments = (data.get("medicaments") or "").strip()
    notes = (data.get("notes") or "").strip()

    if not patient_id:
        return jsonify({"success": False, "reason": _("Patient non spécifié.")})
    if not diagnostic and not medicaments and not notes:
        return jsonify({"success": False, "reason": _("L'entrée ne peut pas être vide.")})

    patient_id = int(patient_id)

    # Créer l'entrée
    entree_id = insert_entree(patient_id, diagnostic, medicaments, notes, medecin_auteur=medecin)

    # PIPELINE : classification IA + chiffrement si sensible
    contenu = {"diagnostic": diagnostic, "medicaments": medicaments, "notes": notes}
    classification = classify_dossier(contenu)
    sensitive_fields = classification["sensitive_fields"]
    if sensitive_fields:
        encrypted = encrypt_dossier(contenu, sensitive_fields)
        update_entree_encrypted(
            entree_id=entree_id,
            encrypted_diagnostic=encrypted.get("diagnostic", diagnostic),
            encrypted_medicaments=encrypted.get("medicaments", medicaments),
            sensitivity_level=classification["global_sensitivity"],
            encrypted_notes=encrypted.get("notes", notes)
        )

    log_access(medecin,
               f"Ajout d'une entrée au dossier patient #{patient_id}",
               ressource=f"Entrée médicale #{entree_id} · sensibilité : {classification['global_sensitivity']}",
               resultat="accordé")

    return jsonify({
        "success": True,
        "entree_id": entree_id,
        "sensitivity": classification["global_sensitivity"],
        "chiffre": bool(sensitive_fields),
        "message": _("Entrée ajoutée à l'historique du patient.")
    })


# ── Vue patient : consulter SON propre dossier (lecture seule) ────────────────
@app.route("/api/mon-dossier")
@login_required
def api_mon_dossier():
    """Le patient consulte son propre dossier + historique, déchiffré, en lecture seule.
    Vérification stricte : il ne peut voir QUE son dossier (via son patient_id)."""
    if session.get("role") != "patient":
        return jsonify({"success": False, "reason": _("Réservé au patient.")}), 403

    from database import get_patient_id_of_user, get_dossier_by_patient, get_entrees_by_patient
    from encryption import decrypt_dossier, dechiffrer_si_chiffre

    username = session.get("username")
    patient_id = get_patient_id_of_user(username)

    if not patient_id:
        return jsonify({"success": False, "reason": _("Aucun dossier associé à votre compte.")})

    historique = []

    # 1. Dossier initial
    dossier = get_dossier_by_patient(patient_id)
    if dossier:
        dossier = dict(dossier)
        if dossier.get("is_encrypted"):
            dechiffre = decrypt_dossier(
                {"diagnostic": dossier.get("diagnostic", ""), "medicaments": dossier.get("medicaments", "")},
                ["diagnostic", "medicaments"]
            )
            dossier["diagnostic"] = dechiffre.get("diagnostic", dossier["diagnostic"])
            dossier["medicaments"] = dechiffre.get("medicaments", dossier["medicaments"])
        historique.append({
            "type": "Dossier initial",
            "diagnostic": dossier["diagnostic"],
            "medicaments": dossier["medicaments"],
            "notes": dechiffrer_si_chiffre(dossier.get("notes")),
            "medecin_auteur": dossier.get("medecin_auteur") or "Système (dossier initial)",
            "sensitivity_level": dossier.get("sensitivity_level", "low"),
            "date": str(dossier.get("created_at", ""))
        })

    # 2. Entrées ajoutées
    entrees = get_entrees_by_patient(patient_id)
    for e in entrees:
        e = dict(e)
        if e.get("is_encrypted"):
            dechiffre = decrypt_dossier(
                {"diagnostic": e.get("diagnostic", ""), "medicaments": e.get("medicaments", "")},
                ["diagnostic", "medicaments"]
            )
            e["diagnostic"] = dechiffre.get("diagnostic", e["diagnostic"])
            e["medicaments"] = dechiffre.get("medicaments", e["medicaments"])
        historique.append({
            "type": "Entrée ajoutée",
            "diagnostic": e["diagnostic"],
            "medicaments": e["medicaments"],
            "notes": dechiffrer_si_chiffre(e["notes"]),
            "medecin_auteur": e["medecin_auteur"],
            "sensitivity_level": e["sensitivity_level"],
            "date": str(e["created_at"])
        })

    log_access(username,
               "Consultation de son propre dossier",
               ressource=f"Dossier personnel · {len(historique)} entrée(s)",
               resultat="accordé")

    return jsonify({"success": True, "entrees": historique})


@app.route("/api/historique/<int:patient_id>")
@login_required
def api_historique(patient_id):
    """Consulter l'historique complet d'un patient (médecin uniquement) :
    le dossier initial + toutes les entrées ajoutées ensuite. Rien n'est écrasé."""
    if session.get("role") != "medecin":
        return jsonify({"success": False, "reason": _("Réservé au médecin.")}), 403

    from database import get_entrees_by_patient, get_dossier_by_patient
    from encryption import decrypt_dossier, dechiffrer_si_chiffre

    historique = []

    # 1. Le dossier initial du patient (table dossiers_medicaux)
    dossier = get_dossier_by_patient(patient_id)
    if dossier:
        dossier = dict(dossier)
        if dossier.get("is_encrypted"):
            dechiffre = decrypt_dossier(
                {"diagnostic": dossier.get("diagnostic", ""), "medicaments": dossier.get("medicaments", "")},
                ["diagnostic", "medicaments"]
            )
            dossier["diagnostic"] = dechiffre.get("diagnostic", dossier["diagnostic"])
            dossier["medicaments"] = dechiffre.get("medicaments", dossier["medicaments"])
        historique.append({
            "id": f"initial-{dossier['id']}",
            "type": "Dossier initial",
            "diagnostic": dossier["diagnostic"],
            "medicaments": dossier["medicaments"],
            "notes": dechiffrer_si_chiffre(dossier.get("notes")),
            "medecin_auteur": dossier.get("medecin_auteur") or "Système (dossier initial)",
            "sensitivity_level": dossier.get("sensitivity_level", "low"),
            "date": str(dossier.get("created_at", ""))
        })

    # 2. Les entrées ajoutées ensuite (table entrees_dossier)
    entrees = get_entrees_by_patient(patient_id)
    for e in entrees:
        e = dict(e)
        if e.get("is_encrypted"):
            dechiffre = decrypt_dossier(
                {"diagnostic": e.get("diagnostic", ""), "medicaments": e.get("medicaments", "")},
                ["diagnostic", "medicaments"]
            )
            e["diagnostic"] = dechiffre.get("diagnostic", e["diagnostic"])
            e["medicaments"] = dechiffre.get("medicaments", e["medicaments"])
        historique.append({
            "id": e["id"],
            "type": "Entrée ajoutée",
            "diagnostic": e["diagnostic"],
            "medicaments": e["medicaments"],
            "notes": dechiffrer_si_chiffre(e["notes"]),
            "medecin_auteur": e["medecin_auteur"],
            "sensitivity_level": e["sensitivity_level"],
            "date": str(e["created_at"])
        })

    log_access(session.get("username"),
               f"Consultation du dossier patient #{patient_id}",
               ressource=f"Historique médical · {len(historique)} entrée(s) consultée(s)",
               resultat="accordé")

    return jsonify({"success": True, "entrees": historique})

@app.route("/logs")
@login_required
def logs():
    return jsonify(get_all_logs())


@app.route("/alertes")
@login_required
def alertes():
    return jsonify(get_all_alertes())

@app.route("/api/attempt-action", methods=["POST"])
def api_attempt_action():
    """Route de démonstration d'escalade de privilèges.
    Un attaquant ayant compromis un compte tente une action au-dessus de ses droits.
    La tentative est vérifiée par le RBAC puis journalisée — ce qui permet
    au moteur de détection de repérer une escalade de privilèges.
    """
    from rbac import User, check_access
    data = request.get_json()
    username = data.get("username")
    permission = data.get("permission")

    utilisateur = get_utilisateur_by_username(username)
    if not utilisateur:
        return jsonify({"success": False, "reason": _("Utilisateur introuvable")})
    
    user = User(
        username=utilisateur["username"],
        nom=utilisateur["nom"],
        prenom=utilisateur["prenom"],
        role=utilisateur["role"]
    )
    access = check_access(user, permission)

    log_access(
        utilisateur_id=username,
        action=permission,
        ressource="tentative_action_privilegiee",
        resultat=access["resultat"]
    )

    return jsonify({
        "success": access["allowed"],
        "role": user.role,
        "permission": permission,
        "resultat": access["resultat"]
    }) 

    
@app.route("/security/scan")
@login_required
def security_scan():
    """Lance un scan de sécurité et retourne les menaces détectées + comptes bloqués."""
    rapport = scan_complet()
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT username, role FROM utilisateurs WHERE est_bloque = 1
    """)
    comptes_bloques = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return jsonify({
        "menaces_detectees": rapport["menaces_detectees"],
        "nouvelles_alertes": rapport["nouvelles_alertes"],
        "comptes_bloques": comptes_bloques
    })

@app.route("/security/status")
@login_required
def security_status():
    """Retourne l'état actuel (alertes + comptes bloqués) SANS relancer de scan.
    Utilisé pour rafraîchir l'affichage après un déblocage, sans re-déclencher
    la détection qui rebloquerait le compte."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT username, role FROM utilisateurs WHERE est_bloque = 1")
    comptes_bloques = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return jsonify({"comptes_bloques": comptes_bloques})

@app.route("/security/unblock", methods=["POST"])
@login_required
def security_unblock():
    """
    Déblocage d'un compte — protocole de sécurité renforcé :
    1. Réservé à l'admin
    2. Ré-authentification (mot de passe admin)
    3. Catégorie de motif obligatoire (liste contrôlée)
    4. Motif détaillé substantiel (validé)
    5. Traçabilité inaltérable dans le journal d'audit
    """
    if session.get("role") != "admin":
       return jsonify({"success": False, "reason": _("Action réservée à l'administrateur")}), 403

    from auth import verify_password
    data = request.get_json()
    username = data.get("username")
    admin_password = data.get("admin_password")
    categorie = (data.get("categorie") or "").strip()
    motif = (data.get("motif") or "").strip()

    CATEGORIES_VALIDES = ["Identité vérifiée", "Incident de sécurité traité", "Test de sécurité"]

    # 1. Ré-authentification de l'admin
    admin_user = get_user_auth(session.get("username"))
    if not admin_user or not verify_password(admin_password or "", admin_user["password_hash"]):
        log_access(session.get("username"),
                   f"Tentative de déblocage de {username} — mot de passe admin incorrect",
                   resultat="refusé")
        return jsonify({"success": False, "reason": _("Mot de passe administrateur incorrect.")})

    # 2. Catégorie obligatoire et valide
    if categorie not in CATEGORIES_VALIDES:
        return jsonify({"success": False, "reason": _("Catégorie de motif invalide ou manquante.")})

    # 3. Motif substantiel : au moins 10 caractères, au moins 3 mots, pas de caractère répété
    if len(motif) < 10:
        return jsonify({"success": False, "reason": _("Le motif doit contenir au moins 10 caractères.")})
    if len(set(motif.replace(" ", ""))) < 4:
        return jsonify({"success": False, "reason": _("Le motif n'est pas suffisamment explicite.")})
    if len(motif.split()) < 3:
       return jsonify({"success": False, "reason": _("Le motif doit être une justification (au moins 3 mots).")})

    # 4. Déblocage effectif
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE utilisateurs SET est_bloque = 0 WHERE username = %s", (username,))
    # On efface les alertes de ce compte pour que le scan ne le re-bloque pas :
    # le déblocage administrateur fait autorité sur la détection automatique.
    cursor.execute("DELETE FROM alertes WHERE username = %s", (username,))
    conn.commit()
    conn.close()

    # 5. Traçabilité enrichie
    log_access(
        session.get("username"),
        f"Déblocage du compte {username}",
        ressource=f"Catégorie : {categorie}  ·  Motif : {motif.strip()}",
        resultat="accordé"
    )

    # 6. Après un incident, la confiance accordée aux appareils de ce compte est
    #    retirée : la 2FA complète sera de nouveau exigée partout.
    nb_revoques = trusted_device.revoquer_tous(username)
    if nb_revoques:
        log_access(
            session.get("username"),
            f"Révocation des appareils de confiance du compte {username} ({nb_revoques})",
            ressource="Appareil de confiance",
            resultat="accordé"
        )
    return jsonify({"success": True, "message": _("Compte %(user)s débloqué") % {"user": username}})   


@app.route("/stats")
@login_required
def stats():
    return jsonify({
        "sensitivity": get_stats_sensitivity(),
        "access_by_role": get_stats_access_by_role(),
        "counters": get_stats_counters()
    })

def calculer_conformite():
    """Calcule le score de conformité RGPD/HDS.
    Partagé par /conformite (JSON pour le tableau de bord) et /rapport-pdf."""
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) as t FROM dossiers_medicaux")
    total = cursor.fetchone()["t"] or 1
    cursor.execute("SELECT COUNT(*) as t FROM dossiers_medicaux WHERE is_encrypted=1")
    chiffres = cursor.fetchone()["t"]
    score_chiffrement = round((chiffres / total) * 100)

    cursor.execute("SELECT COUNT(*) as t FROM audit_logs")
    total_logs = cursor.fetchone()["t"] or 0
    score_logs = min(100, int((total_logs / max(total, 1)) * 100))

    cursor.execute("SELECT COUNT(*) as t FROM alertes")
    nb_alertes = cursor.fetchone()["t"] or 0
    score_rbac = max(30, 100 - (nb_alertes * 10))

    cursor.execute("""
        SELECT COUNT(*) as t FROM patients
        WHERE nom IS NOT NULL AND prenom IS NOT NULL
        AND nir IS NOT NULL AND date_naissance IS NOT NULL
    """)
    complets = cursor.fetchone()["t"]
    score_obligatoire = round((complets / total) * 100)
    conn.close()

    score_global = int(
        score_chiffrement * 0.30 + score_logs * 0.30 +
        score_rbac * 0.20 + score_obligatoire * 0.20
    )


    if score_global >= 80:
        statut, message = "success", _("Conforme — Système hautement sécurisé")
    elif score_global >= 60:
        statut, message = "warning", _("Avertissement — Des vulnérabilités sont présentes")
    else:
        statut, message = "danger", _("Non conforme — Action corrective requise")

    return {
        "score_global": score_global,
        "chiffrement": score_chiffrement,
        "logs": score_logs,
        "rbac": score_rbac,
        "obligatoire": score_obligatoire,
        "statut": statut,
        "message": message
    }


@app.route("/conformite")
@login_required
def conformite():
    return jsonify(calculer_conformite())

@app.route("/rapport-pdf")
@login_required
def rapport_pdf():
    from datetime import datetime
    from io import BytesIO
    from reportlab.lib.pagesizes import A4
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    )
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib import colors

    from flask_babel import force_locale

    # Calcul direct (plus de requête interne avec une session fabriquée).
    # Le rapport PDF est rédigé en français : le message de statut l'est aussi.
    with force_locale("fr"):
        data = calculer_conformite()

    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4,
                            rightMargin=40, leftMargin=40,
                            topMargin=40, bottomMargin=40)
    styles = getSampleStyleSheet()
    NAVY  = colors.HexColor("#1E2761")
    TEAL  = colors.HexColor("#00C2CB")
    WHITE = colors.white

    def h1(t): return Paragraph(t, ParagraphStyle("h1", parent=styles["Heading1"],
        fontSize=20, textColor=NAVY, alignment=1, spaceAfter=12))
    def h2(t): return Paragraph(t, ParagraphStyle("h2", parent=styles["Heading2"],
        fontSize=13, textColor=TEAL, spaceBefore=14, spaceAfter=6))
    def body(t): return Paragraph(t, ParagraphStyle("body", parent=styles["BodyText"],
        fontSize=10, spaceAfter=6))

    story = [
        h1("TCIM — Rapport de Conformité RGPD"),
        body(f"<i>Généré le {datetime.now().strftime('%d/%m/%Y à %H:%M:%S')}</i>"),
        Spacer(1, 12),
        h2("1. Résumé exécutif"),
        body(f"Score global de conformité : <b>{data['score_global']}/100</b>"),
        body(f"Statut : <b>{data['message']}</b>"),
        Spacer(1, 8),
        h2("2. Analyse détaillée par critère"),
    ]
    tableau = [
        ["Critère RGPD", "Score", "Poids", "Statut"],
        ["Chiffrement (AES-128-CBC + HMAC-SHA256)", f"{data['chiffrement']}/100", "30%",
         "Conforme" if data["chiffrement"] >= 80 else "À améliorer"],
        ["Couverture logs d'audit", f"{data['logs']}/100", "30%",
         "Conforme" if data["logs"] >= 80 else "À améliorer"],
        ["Respect RBAC & sécurité", f"{data['rbac']}/100", "20%",
         "Conforme" if data["rbac"] >= 80 else "Alerte active"],
        ["Données obligatoires", f"{data['obligatoire']}/100", "20%",
         "Conforme" if data["obligatoire"] >= 80 else "Incomplet"],
    ]
    t = Table(tableau, colWidths=[230, 70, 60, 100])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), NAVY),
        ("TEXTCOLOR", (0,0), (-1,0), WHITE),
        ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.HexColor("#F0F4FF"), WHITE]),
        ("GRID", (0,0), (-1,-1), 0.5, colors.HexColor("#E2E8F0")),
        ("FONTSIZE", (0,0), (-1,-1), 9),
        ("TOPPADDING", (0,0), (-1,-1), 7),
        ("BOTTOMPADDING", (0,0), (-1,-1), 7),
    ]))
    story.append(t)
    story.append(Spacer(1, 14))
    story.append(h2("3. Recommandations"))
    if data["score_global"] >= 80:
        story.append(body("✓ Aucune action corrective urgente. Le système respecte "
            "les standards HDS. Maintenir les audits réguliers."))
    else:
        story.append(body("• Chiffrement : planifier une rotation des clés Fernet (AES-128-CBC + HMAC-SHA256)."))
        story.append(body("• RBAC : restreindre les comptes suspects suite aux alertes."))
        story.append(body("• Logs : exporter vers un serveur sécurisé externe."))
    story.append(Spacer(1, 20))
    story.append(body("<i>TCIM — Sécurisation des données de santé par l'IA</i>"))

    doc.build(story)
    buffer.seek(0)
    return send_file(buffer, as_attachment=True,
        download_name=f"Rapport_RGPD_{datetime.now().strftime('%Y%m%d')}.pdf",
        mimetype="application/pdf")


def chiffrer_tous_les_dossiers():
    from classifier import classify_dossier
    from encryption import encrypt_dossier
    from database import update_dossier_encrypted
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, patient_id, diagnostic, medicaments,
               notes, is_encrypted, sensitivity_level
        FROM dossiers_medicaux WHERE is_encrypted = 0
    """)
    dossiers = cursor.fetchall()
    conn.close()

    chiffres = 0
    for d in dossiers:
        dossier_dict = {
            "diagnostic": d["diagnostic"] or "",
            "medicaments": d["medicaments"] or "",
            "notes": d["notes"] or ""
        }
        classification = classify_dossier(dossier_dict)
        sensitive_fields = classification["sensitive_fields"]
        if sensitive_fields:
            encrypted = encrypt_dossier(dossier_dict, sensitive_fields)
            update_dossier_encrypted(
                dossier_id=d["id"],
                encrypted_diagnostic=encrypted.get("diagnostic", d["diagnostic"]),
                encrypted_medicaments=encrypted.get("medicaments", d["medicaments"]),
                sensitivity_level=d["sensitivity_level"],
                encrypted_notes=encrypted.get("notes", d["notes"])
            )
            chiffres += 1
    print(f"Chiffrement automatique : {chiffres} dossiers chiffrés.")


def chiffrer_notes_existantes():
    """Migration : chiffre les notes sensibles restées en clair dans les dossiers
    et entrées déjà chiffrés (avant que le champ notes soit pris en charge).
    Même classification et même chiffrement que pour les autres champs : une
    note n'est chiffrée que si elle est classée sensible. Sans effet si elle
    est déjà chiffrée, donc relançable sans risque."""
    from classifier import classify_dossier
    from encryption import encrypt_dossier, est_chiffre
    from database import update_notes_chiffrees
    migrees = 0
    for table in ("dossiers_medicaux", "entrees_dossier"):
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute(f"""
            SELECT id, notes FROM {table}
            WHERE is_encrypted = 1 AND COALESCE(notes, '') <> ''
        """)
        lignes = cursor.fetchall()
        conn.close()
        for ligne in lignes:
            if est_chiffre(ligne["notes"]):
                continue
            contenu = {"notes": ligne["notes"]}
            if "notes" in classify_dossier(contenu)["sensitive_fields"]:
                update_notes_chiffrees(table, ligne["id"],
                                       encrypt_dossier(contenu, ["notes"])["notes"])
                migrees += 1
    print(f"Chiffrement des notes existantes : {migrees} note(s) chiffrée(s).")


if __name__ == "__main__":
    init_audit_tables()
    trusted_device.init_table()
    chiffrer_tous_les_dossiers()
    chiffrer_notes_existantes()
    app.run(debug=True, host="0.0.0.0", port=5000)