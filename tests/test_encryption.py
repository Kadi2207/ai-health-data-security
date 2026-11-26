import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from dotenv import load_dotenv
load_dotenv()

from encryption import encrypt, decrypt, encrypt_dossier, decrypt_dossier

# ── Tests encrypt / decrypt ───────────────────────────────────────────────────

def test_encrypt_retourne_chaine():
    result = encrypt("Diabète de type 2")
    assert isinstance(result, str)
    assert result != "Diabète de type 2"

def test_decrypt_retrouve_original():
    original = "Cancer du poumon — Morphine 10mg"
    token = encrypt(original)
    result = decrypt(token)
    assert result == original

def test_encrypt_decrypt_nir():
    nir = "178054412345678"
    token = encrypt(nir)
    assert token != nir
    assert decrypt(token) == nir

def test_encrypt_chaine_vide():
    result = encrypt("")
    assert result == ""

def test_decrypt_chaine_vide():
    result = decrypt("")
    assert result == ""

def test_deux_chiffrements_differents():
    texte = "Données sensibles"
    token1 = encrypt(texte)
    token2 = encrypt(texte)
    assert token1 != token2

# ── Tests encrypt_dossier / decrypt_dossier ───────────────────────────────────

def test_encrypt_dossier_champs_sensibles():
    dossier = {
        "diagnostic": "Diabète de type 2",
        "medicaments": "Metformine 500mg",
        "notes": "Suivi régulier"
    }
    sensitive_fields = ["diagnostic", "medicaments"]
    result = encrypt_dossier(dossier, sensitive_fields)

    assert result["diagnostic"] != dossier["diagnostic"]
    assert result["medicaments"] != dossier["medicaments"]
    assert result["notes"] == dossier["notes"]

def test_decrypt_dossier_retrouve_original():
    dossier = {
        "diagnostic": "VIH contrôlé sous traitement",
        "medicaments": "Ténofovir 300mg",
        "notes": "Consultation mensuelle"
    }
    sensitive_fields = ["diagnostic", "medicaments"]
    encrypted = encrypt_dossier(dossier, sensitive_fields)
    decrypted = decrypt_dossier(encrypted, sensitive_fields)

    assert decrypted["diagnostic"] == dossier["diagnostic"]
    assert decrypted["medicaments"] == dossier["medicaments"]
    assert decrypted["notes"] == dossier["notes"]

def test_encrypt_dossier_sans_champs_sensibles():
    dossier = {
        "diagnostic": "Diabète de type 2",
        "notes": "Suivi régulier"
    }
    result = encrypt_dossier(dossier, [])
    assert result["diagnostic"] == dossier["diagnostic"]
    assert result["notes"] == dossier["notes"]

# ── Lancement direct ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    tests = [
        test_encrypt_retourne_chaine,
        test_decrypt_retrouve_original,
        test_encrypt_decrypt_nir,
        test_encrypt_chaine_vide,
        test_decrypt_chaine_vide,
        test_deux_chiffrements_differents,
        test_encrypt_dossier_champs_sensibles,
        test_decrypt_dossier_retrouve_original,
        test_encrypt_dossier_sans_champs_sensibles
    ]

    print("=== Tests Encryption ===\n")
    passed = 0
    failed = 0
    for test in tests:
        try:
            test()
            print(f"  ✅ {test.__name__}")
            passed += 1
        except AssertionError as e:
            print(f"  ❌ {test.__name__} — {e}")
            failed += 1

    print(f"\nRésultat : {passed} réussis / {failed} échoués")