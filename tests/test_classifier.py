import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from classifier import classify_dossier, detect_sensitive_fields

# ── Tests detect_sensitive_fields ────────────────────────────────────────────

def test_detection_diagnostic_sensible():
    dossier = {"diagnostic": "Diabète de type 2"}
    result = detect_sensitive_fields(dossier)
    assert result["diagnostic"]["is_sensitive"] is True

def test_detection_champ_non_sensible():
    dossier = {"notes": "Rendez-vous pris pour le mois prochain"}
    result = detect_sensitive_fields(dossier)
    assert result["notes"]["is_sensitive"] is False

def test_detection_nir():
    dossier = {"nir": "178054412345678"}
    result = detect_sensitive_fields(dossier)
    assert result["nir"]["score"] >= 3

def test_detection_date_naissance():
    dossier = {"date_naissance": "12/05/1978"}
    result = detect_sensitive_fields(dossier)
    assert result["date_naissance"]["score"] >= 1

# ── Tests classify_dossier ────────────────────────────────────────────────────

def test_classification_high():
    dossier = {
        "diagnostic": "Cancer du poumon",
        "medicaments": "Morphine 10mg",
        "nir": "178054412345678",
        "notes": "Traitement en phytothérapie"
    }
    result = classify_dossier(dossier)
    assert result["global_sensitivity"] in ("medium", "high")
    assert result["total_score"] >= 2

def test_classification_low():
    dossier = {
        "notes": "Rendez-vous confirmé dans 6 mois",
        "statut": "Patient en bonne santé générale"
    }
    result = classify_dossier(dossier)
    assert result["global_sensitivity"] in ("low", "medium")
def test_champs_sensibles_detectes():
    dossier = {
        "diagnostic": "VIH contrôlé sous traitement",
        "medicaments": "Ténofovir 300mg",
        "notes": "Suivi régulier"
    }
    result = classify_dossier(dossier)
    assert "diagnostic" in result["sensitive_fields"]

def test_dossier_vide():
    dossier = {}
    result = classify_dossier(dossier)
    assert result["total_score"] == 0
    assert result["sensitive_fields"] == []

# ── Lancement direct ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    tests = [
        test_detection_diagnostic_sensible,
        test_detection_champ_non_sensible,
        test_detection_nir,
        test_detection_date_naissance,
        test_classification_high,
        test_classification_low,
        test_champs_sensibles_detectes,
        test_dossier_vide
    ]

    print("=== Tests Classifier ===\n")
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