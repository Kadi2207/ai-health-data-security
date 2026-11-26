import bcrypt
import pyotp
import qrcode
import io
import base64
from database import get_connection


# ── Hachage des mots de passe (bcrypt) ───────────────────────────────────────
def hash_password(password: str) -> str:
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode("utf-8"), salt)
    return hashed.decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    if not password_hash:
        return False
    return bcrypt.checkpw(
        password.encode("utf-8"),
        password_hash.encode("utf-8")
    )


# ── Gestion 2FA (TOTP — compatible Google/Microsoft Authenticator) ───────────
def generate_otp_secret() -> str:
    return pyotp.random_base32()


def get_totp_uri(username: str, secret: str) -> str:
    return pyotp.totp.TOTP(secret).provisioning_uri(
        name=username,
        issuer_name="TCIM Santé"
    )


def generate_qr_code(uri: str) -> str:
    """Génère un QR code en base64 affichable dans le navigateur."""
    qr = qrcode.make(uri)
    buffer = io.BytesIO()
    qr.save(buffer, format="PNG")
    buffer.seek(0)
    img_base64 = base64.b64encode(buffer.read()).decode("utf-8")
    return f"data:image/png;base64,{img_base64}"


def verify_otp(secret: str, code: str) -> bool:
    if not secret or not code:
        return False
    totp = pyotp.TOTP(secret)
    return totp.verify(code, valid_window=1)


# ── Opérations base de données ────────────────────────────────────────────────
def set_user_credentials(username: str, password: str):
    """Définit le mot de passe haché et le secret 2FA d'un utilisateur."""
    password_hash = hash_password(password)
    otp_secret = generate_otp_secret()
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE utilisateurs
        SET password_hash = %s, otp_secret = %s
        WHERE username = %s
    """, (password_hash, otp_secret, username))
    conn.commit()
    conn.close()
    return otp_secret


def get_user_auth(username: str):
    """Récupère les infos d'authentification d'un utilisateur."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT username, role, password_hash, otp_secret
        FROM utilisateurs WHERE username = %s
    """, (username,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def authenticate(username: str, password: str) -> dict:
    """Vérifie username + mot de passe. Retourne le statut."""
    user = get_user_auth(username)
    if not user:
        return {"success": False, "reason": "Utilisateur introuvable"}
    if not verify_password(password, user["password_hash"]):
        return {"success": False, "reason": "Mot de passe incorrect"}
    return {
        "success": True,
        "username": user["username"],
        "role": user["role"],
        "has_2fa": bool(user["otp_secret"])
    }