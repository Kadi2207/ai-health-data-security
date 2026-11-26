import os
import sys
from dotenv import load_dotenv

load_dotenv()

from database import (
    get_connection, get_dossier_by_patient,
    get_utilisateur_by_username, update_dossier_encrypted,
    get_patient_id_of_user
)

from classifier import classify_dossier
from encryption import encrypt_dossier, decrypt_dossier, dechiffrer_si_chiffre
from rbac import User, check_access
from audit_log import log_access


def process_dossier(patient_id: int, username: str, permission: str) -> dict:
    """
    Pipeline complet :
    1. Récupérer le dossier patient
    2. Classifier les données sensibles
    3. Vérifier les droits RBAC
    4. Chiffrer si sensible
    5. Logger l'accès
    6. Retourner le résultat
    """

    # 1. Récupérer l'utilisateur
    utilisateur = get_utilisateur_by_username(username)
    if not utilisateur:
        return {"erreur": f"Utilisateur '{username}' introuvable."}

    user = User(
        username=utilisateur["username"],
        nom=utilisateur["nom"],
        prenom=utilisateur["prenom"],
        role=utilisateur["role"]
    )

    # 2. Récupérer le dossier
    dossier_row = get_dossier_by_patient(patient_id)
    if not dossier_row:
        return {"erreur": f"Dossier introuvable pour patient_id={patient_id}"}

    dossier = dict(dossier_row)

    # 3. Classifier
    dossier_a_classifier = {
        "diagnostic": dossier.get("diagnostic", ""),
        "medicaments": dossier.get("medicaments", ""),
        "notes": dossier.get("notes", "")
    }
    classification = classify_dossier(dossier_a_classifier)

    # 4. Vérifier accès RBAC
    access_result = check_access(user, permission)

    # 4bis. CONFIDENTIALITÉ : un patient ne peut accéder QU'À son propre dossier.
    # Même s'il a la permission de lecture, on vérifie que le dossier est bien le sien.
    if user.role == "patient":
        mon_patient_id = get_patient_id_of_user(username)
        if mon_patient_id != patient_id:
            log_access(
                utilisateur_id=username,
                action=permission,
                ressource=f"dossier_id={dossier['id']} (dossier d'autrui)",
                resultat="refusé"
            )
            return {
                "access": "refusé",
                "username": username,
                "role": user.role,
                "permission": permission,
                "message": "Accès refusé — vous ne pouvez consulter que votre propre dossier."
            }

    resultat_log = access_result["resultat"]

    # 5. Logger l'accès
    log_access(
        utilisateur_id=utilisateur["username"],
        action=permission,
        ressource=f"dossier_id={dossier['id']}",
        resultat=resultat_log
    )

    # 6. Si accès refusé → retourner sans données
    if not access_result["allowed"]:
        return {
            "access": "refusé",
            "username": username,
            "role": user.role,
            "permission": permission,
            "message": "Accès refusé — droits insuffisants."
        }

    # 7. État chiffré en base (tel que stocké)
    sensitive_fields = classification["sensitive_fields"]

    # Si le dossier n'est pas encore chiffré, on le chiffre maintenant
    if sensitive_fields and not dossier.get("is_encrypted"):
        dossier_chiffre = encrypt_dossier(dossier_a_classifier, sensitive_fields)
        update_dossier_encrypted(
            dossier_id=dossier["id"],
            encrypted_diagnostic=dossier_chiffre.get("diagnostic", dossier["diagnostic"]),
            encrypted_medicaments=dossier_chiffre.get("medicaments", dossier["medicaments"]),
            sensitivity_level=classification["global_sensitivity"],
            encrypted_notes=dossier_chiffre.get("notes", dossier["notes"])
        )
        dossier["diagnostic"] = dossier_chiffre.get("diagnostic", dossier["diagnostic"])
        dossier["medicaments"] = dossier_chiffre.get("medicaments", dossier["medicaments"])
        dossier["notes"] = dossier_chiffre.get("notes", dossier["notes"])
        dossier["is_encrypted"] = 1

    # 8. Version chiffrée (telle qu'en base) — preuve du stockage sécurisé
    donnees_chiffrees = {
        "diagnostic": dossier.get("diagnostic"),
        "medicaments": dossier.get("medicaments")
    }

    # 9. Déchiffrement pour l'utilisateur autorisé — preuve du cycle complet
    donnees_dechiffrees = decrypt_dossier(
        {
            "diagnostic": dossier.get("diagnostic", ""),
            "medicaments": dossier.get("medicaments", "")
        },
        ["diagnostic", "medicaments"]
    )

    # 10. Retourner le résultat complet
    return {
        "access": "accordé",
        "username": username,
        "role": user.role,
        "permission": permission,
        "patient_id": patient_id,
        "classification": {
            "global_sensitivity": classification["global_sensitivity"],
            "total_score": classification["total_score"],
            "sensitive_fields": sensitive_fields,
            "model_accuracy": classification.get("model_accuracy")
        },
        "is_encrypted": bool(dossier.get("is_encrypted")),
        "donnees_chiffrees": donnees_chiffrees,
        "donnees_dechiffrees": donnees_dechiffrees,
        "notes": dechiffrer_si_chiffre(dossier.get("notes")),
        "sensitivity_level": dossier.get("sensitivity_level")
    }