import re
import os
import pickle

# ── Chemins ──────────────────────────────────────────────────────────────────
MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "model.pkl")

# ── Cache modèle ─────────────────────────────────────────────────────────────
_model_cache = None
_accuracy_cache = None


def load_model():
    global _model_cache, _accuracy_cache
    if _model_cache is None:
        if not os.path.exists(MODEL_PATH):
            return None, None
        with open(MODEL_PATH, "rb") as f:
            data = pickle.load(f)
        _model_cache = data["pipeline"]
        _accuracy_cache = data["accuracy"]
    return _model_cache, _accuracy_cache


def get_model_accuracy():
    _, accuracy = load_model()
    return round(accuracy * 100, 1) if accuracy else None


# ── Layer 1 — Règles déterministes (sécurité critique) ───────────────────────
NIR_PATTERN    = re.compile(r"\b[12]\d{2}(0[1-9]|1[0-2])\d{2}\d{3}\d{3}\d{2}\b")
DATE_PATTERN   = re.compile(r"\b\d{2}/\d{2}/\d{4}\b")
EMAIL_PATTERN  = re.compile(r"\b[\w.+-]+@[\w-]+\.[a-z]{2,}\b", re.IGNORECASE)
PHONE_PATTERN  = re.compile(r"\b0[1-9](\s?\d{2}){4}\b")
DOCTOR_PATTERN = re.compile(r"\bDr\.?\s+[A-ZÀ-Ÿ][a-zà-ÿ]+", re.UNICODE)

CRITICAL_KEYWORDS = {
    # Français
    "VIH", "SIDA", "séropositif", "séropositivité",
    "cancer", "leucémie", "chimiothérapie",
    "schizophrénie", "psychose", "psychiatrique",
    "morphine", "méthadone", "stupéfiant",
    "ordonnance sécurisée", "suicidaire", "hospitalisation sous contrainte",
    # English
    "HIV", "AIDS", "seropositive",
    "leukemia", "chemotherapy",
    "schizophrenia", "psychosis", "psychiatric",
    "methadone", "narcotic",
    "controlled substance", "suicidal", "involuntary commitment"
}

def layer1_check(text: str) -> dict:
    matched_rules = []
    if NIR_PATTERN.search(text):
        matched_rules.append("NIR")
    if DATE_PATTERN.search(text):
        matched_rules.append("date")
    if EMAIL_PATTERN.search(text):
        matched_rules.append("email")
    if PHONE_PATTERN.search(text):
        matched_rules.append("téléphone")
    if DOCTOR_PATTERN.search(text):
        matched_rules.append("praticien")
    for kw in CRITICAL_KEYWORDS:
        if kw.lower() in text.lower():
            matched_rules.append(f"mot-clé:{kw}")
            break
    return {
        "triggered": len(matched_rules) > 0,
        "rules": matched_rules
    }


# ── Layer 2 — Modèle ML (classification supervisée TF-IDF) ───────────────────
def layer2_predict(text: str, lang: str = "fr") -> dict:
    # Le modèle TF-IDF est entraîné sur un corpus exclusivement français.
    # Sur une autre langue, ses prédictions ne sont pas fiables : on le
    # court-circuite proprement et on laisse Layer 1 (bilingue) + le défaut
    # « low » décider. La couche ML est donc spécialisée FR, par conception.
    if lang != "fr":
        return {"available": False, "proba_high": 0.0, "proba_low": 0.0}
    model, _ = load_model()
    if model is None:
        return {"available": False, "proba_high": 0.0, "proba_low": 0.0}
    proba = model.predict_proba([text])[0]
    classes = model.classes_
    proba_dict = dict(zip(classes, proba))
    return {
        "available": True,
        "proba_high": round(float(proba_dict.get(1, 0.0)), 3),
        "proba_low": round(float(proba_dict.get(0, 0.0)), 3),
    }


# ── Layer 3 — Decision engine (fusion conservative) ──────────────────────────
def layer3_decide(l1: dict, l2: dict) -> dict:
    # Layer 1 override — sécurité critique
    if l1["triggered"]:
        return {
            "sensitivity": "high",
            "is_sensitive": True,
            "source": "layer1_rules",
            "rules_matched": l1["rules"]
        }

    # Layer 2 — modèle ML
    if l2["available"]:
        if l2["proba_high"] >= 0.7:
            return {
                "sensitivity": "high",
                "is_sensitive": True,
                "source": "layer2_ml",
                "confidence": l2["proba_high"]
            }
        elif l2["proba_high"] >= 0.5:
            return {
                "sensitivity": "medium",
                "is_sensitive": True,
                "source": "layer2_ml",
                "confidence": l2["proba_high"]
            }

    return {
        "sensitivity": "low",
        "is_sensitive": False,
        "source": "layer3_default",
        "flag_review": l2.get("proba_high", 0) >= 0.3
    }


# ── Interface publique ────────────────────────────────────────────────────────
def classify_field(text: str, lang: str = "fr") -> dict:
    if not isinstance(text, str) or not text.strip():
        return {
            "sensitivity": "low",
            "is_sensitive": False,
            "source": "empty",
            "score": 0
        }
    l1 = layer1_check(text)
    l2 = layer2_predict(text, lang)
    decision = layer3_decide(l1, l2)
    score = {"low": 0, "medium": 2, "high": 4}[decision["sensitivity"]]
    return {**decision, "score": score}


def detect_sensitive_fields(dossier: dict, lang: str = "fr") -> dict:
    return {
        field: {**classify_field(value, lang), "value": value}
        for field, value in dossier.items()
        if isinstance(value, str) and value.strip()
    }


def classify_dossier(dossier: dict, lang: str = "fr") -> dict:
    field_results = detect_sensitive_fields(dossier, lang)
    sensitive_fields = [f for f, r in field_results.items() if r["is_sensitive"]]
    total_score = sum(r["score"] for r in field_results.values())

    # Override sécurité : si un seul champ est déclenché par Layer 1 (mot-clé
    # critique ou NIR — donnée de santé protégée), tout le dossier hérite du
    # niveau « high ». On ne moyenne jamais la sensibilité : une seule donnée
    # critique suffit à rendre le dossier critique (principe de précaution).
    layer1_triggered = any(
        r.get("source") == "layer1_rules" for r in field_results.values()
    )

    if layer1_triggered or total_score >= 6:
        global_sensitivity = "high"
    elif total_score >= 2:
        global_sensitivity = "medium"
    else:
        global_sensitivity = "low"

    return {
        "global_sensitivity": global_sensitivity,
        "total_score": total_score,
        "sensitive_fields": sensitive_fields,
        "field_details": field_results,
        "model_accuracy": get_model_accuracy()
    }


if __name__ == "__main__":
    tests = [
        {
            "label": "Dossier critique (NIR + VIH)",
            "data": {
                "nir": "178054412345678",
                "diagnostic": "Séropositif VIH sous Ténofovir",
                "notes": "Suivi mensuel infectiologue"
            }
        },
        {
            "label": "Dossier medium (diagnostic sensible)",
            "data": {
                "diagnostic": "Diabète de type 2 sous Metformine",
                "notes": "Suivi en phytothérapie complémentaire"
            }
        },
        {
            "label": "Dossier non sensible",
            "data": {
                "notes": "Rendez-vous de contrôle dans 6 mois",
                "statut": "Patient en bonne santé générale"
            }
        },
        {
            "label": "English critical record (HIV)",
            "lang": "en",
            "data": {
                "diagnostic": "HIV controlled under Tenofovir treatment",
                "notes": "Monthly follow-up with infectious disease specialist"
            }
        },
        {
            "label": "English non-sensitive record",
            "lang": "en",
            "data": {
                "diagnostic": "Seasonal allergic rhinitis",
                "notes": "Follow-up appointment in 6 months"
            }
        }
    ]
    print("=== Test architecture 3 couches ===\n")
    for test in tests:
        result = classify_dossier(test["data"], test.get("lang", "fr"))
        print(f"Cas : {test['label']}")
        print(f"  Sensibilité globale : {result['global_sensitivity']}")
        print(f"  Champs sensibles    : {result['sensitive_fields']}")
        print(f"  Score total         : {result['total_score']}")
        print(f"  Accuracy modèle     : {result['model_accuracy']}%")
        print()