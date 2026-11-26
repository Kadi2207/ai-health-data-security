"""
Appareils de confiance : allègement de la double authentification (lot 5).

Principes (non négociables) :
  - le MOT DE PASSE reste exigé à chaque connexion ; seule la 2FA peut être
    sautée, et uniquement sur un appareil enregistré juste après une 2FA réussie ;
  - la 2FA complète reste le chemin par défaut (case non cochée par défaut) ;
  - le cookie ne contient qu'un jeton aléatoire de 256 bits, signé avec la
    SECRET_KEY de l'application (itsdangerous) : HttpOnly, SameSite=Strict,
    Secure dès que l'application est servie en HTTPS ;
  - la base ne stocke que l'EMPREINTE SHA-256 du jeton (une fuite de la table
    ne donne aucun cookie utilisable) ;
  - expiration FIXE de 30 jours contrôlée côté serveur, jamais prolongée à
    l'usage ; révocation possible à tout moment (revoked_at).

Ce module n'appelle ni ne modifie la logique 2FA existante (auth.verify_otp,
route /api/verify-2fa).
"""
import hashlib
import secrets
from datetime import datetime, timedelta

from itsdangerous import BadSignature, URLSafeTimedSerializer

from database import get_connection

DUREE_JOURS = 30
NOM_COOKIE = "msp_appareil_confiance"
# Le cookie n'est envoyé qu'aux routes /api/ (connexion et enregistrement)
CHEMIN_COOKIE = "/api/"
_SEL_SIGNATURE = "msp-tcim-appareil-confiance"

# Résultats possibles de verifier()
VALIDE = "valide"
ABSENT = "absent"              # pas de cookie : 2FA normale, rien à tracer
AUTRE_COMPTE = "autre_compte"  # cookie d'un autre utilisateur du même navigateur
INVALIDE = "invalide"          # signature fausse : cookie falsifié ou corrompu
INCONNU = "inconnu"            # signature correcte mais jeton absent de la base
EXPIRE = "expire"
REVOQUE = "revoque"


def init_table():
    """Crée la table si elle n'existe pas (appelée au démarrage de l'application)."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS appareils_confiance (
            id SERIAL PRIMARY KEY,
            username TEXT NOT NULL REFERENCES utilisateurs(username) ON DELETE CASCADE,
            token_hash TEXT NOT NULL UNIQUE,
            libelle TEXT,
            created_at TIMESTAMP NOT NULL,
            expires_at TIMESTAMP NOT NULL,
            last_used_at TIMESTAMP,
            revoked_at TIMESTAMP
        )
    """)
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_appareils_confiance_username
        ON appareils_confiance (username)
    """)
    conn.commit()
    conn.close()


def _empreinte(jeton):
    return hashlib.sha256(jeton.encode("utf-8")).hexdigest()


def _signataire(secret_key):
    return URLSafeTimedSerializer(secret_key, salt=_SEL_SIGNATURE)


def creer(username, secret_key, libelle=""):
    """Enregistre un nouvel appareil de confiance pour `username`.
    Retourne (valeur_du_cookie_signée, date_d_expiration)."""
    jeton = secrets.token_urlsafe(32)
    maintenant = datetime.now()
    expiration = maintenant + timedelta(days=DUREE_JOURS)

    conn = get_connection()
    cursor = conn.cursor()
    # Hygiène : on retire les jetons expirés de cet utilisateur
    cursor.execute(
        "DELETE FROM appareils_confiance WHERE username = %s AND expires_at < %s",
        (username, maintenant)
    )
    cursor.execute("""
        INSERT INTO appareils_confiance (username, token_hash, libelle, created_at, expires_at)
        VALUES (%s, %s, %s, %s, %s)
    """, (username, _empreinte(jeton), (libelle or "")[:200], maintenant, expiration))
    conn.commit()
    conn.close()

    return _signataire(secret_key).dumps(jeton), expiration


def verifier(valeur_cookie, username, secret_key):
    """Indique si le cookie présenté désigne un appareil de confiance valide
    pour `username` (dont le mot de passe vient d'être vérifié).
    Retourne l'une des constantes VALIDE, ABSENT, AUTRE_COMPTE, INVALIDE,
    INCONNU, EXPIRE, REVOQUE."""
    if not valeur_cookie:
        return ABSENT

    try:
        # max_age : seconde barrière, la date d'expiration en base fait foi
        jeton = _signataire(secret_key).loads(valeur_cookie, max_age=DUREE_JOURS * 86400)
    except BadSignature:  # inclut SignatureExpired
        return INVALIDE
    if not isinstance(jeton, str):
        return INVALIDE

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, username, expires_at, revoked_at
        FROM appareils_confiance WHERE token_hash = %s
    """, (_empreinte(jeton),))
    ligne = cursor.fetchone()

    if ligne is None:
        statut = INCONNU
    elif ligne["username"] != username:
        statut = AUTRE_COMPTE
    elif ligne["revoked_at"] is not None:
        statut = REVOQUE
    elif ligne["expires_at"] <= datetime.now():
        statut = EXPIRE
    else:
        statut = VALIDE
        cursor.execute(
            "UPDATE appareils_confiance SET last_used_at = %s WHERE id = %s",
            (datetime.now(), ligne["id"])
        )
        conn.commit()
    conn.close()
    return statut


def revoquer_tous(username):
    """Révoque tous les appareils de confiance encore actifs d'un utilisateur.
    Retourne le nombre d'appareils révoqués."""
    maintenant = datetime.now()
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE appareils_confiance SET revoked_at = %s
        WHERE username = %s AND revoked_at IS NULL AND expires_at > %s
    """, (maintenant, username, maintenant))
    nombre = cursor.rowcount
    conn.commit()
    conn.close()
    return nombre
