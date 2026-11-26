import os
from cryptography.fernet import Fernet
from dotenv import load_dotenv

load_dotenv()


def load_key() -> bytes:
    key = os.getenv("SECRET_KEY")
    if not key:
        raise ValueError("SECRET_KEY manquante — vérifier le fichier .env")
    return key.encode()


def encrypt(text: str) -> str:
    if not text:
        return text
    f = Fernet(load_key())
    return f.encrypt(text.encode()).decode()


def decrypt(token: str) -> str:
    if not token:
        return token
    f = Fernet(load_key())
    return f.decrypt(token.encode()).decode()


def encrypt_dossier(dossier: dict, sensitive_fields: list) -> dict:
    encrypted = dossier.copy()
    for field in sensitive_fields:
        if field in encrypted and isinstance(encrypted[field], str):
            encrypted[field] = encrypt(encrypted[field])
    return encrypted


def decrypt_dossier(dossier: dict, sensitive_fields: list) -> dict:
    decrypted = dossier.copy()
    for field in sensitive_fields:
        if field in decrypted and isinstance(decrypted[field], str):
            try:
                decrypted[field] = decrypt(decrypted[field])
            except Exception:
                decrypted[field] = "[Erreur déchiffrement]"
    return decrypted


# Tout jeton Fernet commence par ces caractères (octet de version 0x80 suivi
# d'un horodatage), ce qu'un texte médical saisi en clair ne fait pas.
PREFIXE_FERNET = "gAAAAA"


def est_chiffre(valeur) -> bool:
    return isinstance(valeur, str) and valeur.startswith(PREFIXE_FERNET)


def dechiffrer_si_chiffre(valeur):
    """Déchiffre un champ seulement s'il est chiffré.

    Sert au champ « notes » : comme le diagnostic et les médicaments, il n'est
    chiffré que s'il est classé sensible, mais une note non sensible reste en
    clair dans un dossier chiffré. Un jeton altéré donne « [Erreur déchiffrement] »,
    comme avec decrypt_dossier."""
    if not est_chiffre(valeur):
        return valeur
    return decrypt_dossier({"valeur": valeur}, ["valeur"])["valeur"]


if __name__ == "__main__":
    load_dotenv()
    test_text = "Diabète de type 2 — Metformine 500mg"
    print(f"Original    : {test_text}")
    encrypted = encrypt(test_text)
    print(f"Chiffré     : {encrypted}")
    decrypted = decrypt(encrypted)
    print(f"Déchiffré   : {decrypted}")
    print(f"Succès      : {test_text == decrypted}")