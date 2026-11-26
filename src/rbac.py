# Définition des permissions par rôle
ROLES_PERMISSIONS = {
    "admin": [
        "read_dossier",
        "read_logs",
        "manage_users",
        "manage_security"
    ],
    "medecin": [
        "read_dossier",
        "write_dossier"
    ],
    "infirmier": [
        "read_dossier"
    ],
    "patient": [
        # Le patient a la permission de lecture, comme l'infirmier ;
        # c'est la vérification d'appartenance (main_pipeline.py) qui
        # garantit qu'il ne lit QUE son propre dossier, quel que soit
        # le patient_id qu'il demanderait.
        "read_dossier"
    ]
}


class User:
    def __init__(self, username: str, nom: str, prenom: str, role: str):
        if role not in ROLES_PERMISSIONS:
            raise ValueError(f"Rôle invalide : {role}")
        self.username = username
        self.nom = nom
        self.prenom = prenom
        self.role = role

    def __repr__(self):
        return f"User({self.username}, role={self.role})"


def get_permissions(role: str) -> list:
    if role not in ROLES_PERMISSIONS:
        raise ValueError(f"Rôle inconnu : {role}")
    return ROLES_PERMISSIONS[role]


def can_access(user: User, permission: str) -> bool:
    return permission in get_permissions(user.role)


def check_access(user: User, permission: str) -> dict:
    allowed = can_access(user, permission)
    return {
        "username": user.username,
        "role": user.role,
        "permission": permission,
        "resultat": "accordé" if allowed else "refusé",
        "allowed": allowed
    }