import random
from faker import Faker
from database import init_db, insert_patient, insert_dossier, insert_utilisateur

fake = Faker("fr_FR")
Faker.seed(42)
DIAGNOSTICS = [
    "Diabète de type 2", "Hypertension artérielle", "Insuffisance cardiaque",
    "Dépression sévère", "Cancer du poumon", "Tuberculose pulmonaire",
    "Infection urinaire chronique", "Épilepsie", "Schizophrénie",
    "Alzheimer débutant", "Parkinson stade 2", "VIH contrôlé sous traitement",
    "Asthme sévère", "Insuffisance rénale chronique", "Arthrite rhumatoïde",
    "Ostéoporose", "Anxiété généralisée", "Trouble bipolaire",
    "Hépatite C chronique", "Fibromyalgie"
]

MEDICAMENTS = [
    "Metformine 500mg", "Amlodipine 5mg", "Furosémide 40mg",
    "Sertraline 50mg", "Morphine 10mg", "Isoniazide 300mg",
    "Ciprofloxacine 500mg", "Valproate 500mg", "Rispéridone 2mg",
    "Donépézil 10mg", "Lévodopa 250mg", "Ténofovir 300mg",
    "Salbutamol 100mcg", "Érythropoïétine 4000UI", "Méthotrexate 15mg",
    "Calcium 1000mg", "Alprazolam 0.5mg", "Lithium 400mg",
    "Ribavirine 200mg", "Prégabaline 75mg"
]

MEDECINS = [
    "Dr. Martin Sophie", "Dr. Bernard Jean", "Dr. Dubois Marie",
    "Dr. Thomas Pierre", "Dr. Petit Claire", "Dr. Robert Luc",
    "Dr. Leroy Anne", "Dr. Moreau Paul", "Dr. Laurent Hélène",
    "Dr. Simon Jacques"
]

NOTES_TCIM = [
    "Patient suivi en phytothérapie complémentaire.",
    "Acupuncture recommandée en complément du traitement.",
    "Intérêt pour l'homéopathie signalé par le patient.",
    "Suivi ostéopathique en cours.",
    "Traitement naturopathique combiné à la médecine conventionnelle.",
    "Médecine traditionnelle africaine signalée par le patient.",
    "Ayurveda pratiqué en parallèle — informer le médecin des interactions.",
    "Patient réticent aux traitements chimiques — approche TCIM privilégiée.",
    "Suivi régulier toutes les 3 semaines.",
    "Bilan annuel prévu en décembre."
]

ROLES = ["medecin", "patient", "admin", "infirmier"]


def generate_nir():
    sexe = random.choice(["1", "2"])
    annee = str(random.randint(50, 99))
    mois = str(random.randint(1, 12)).zfill(2)
    dept = str(random.randint(1, 95)).zfill(2)
    commune = str(random.randint(1, 999)).zfill(3)
    ordre = str(random.randint(1, 999)).zfill(3)
    cle = str(random.randint(1, 97)).zfill(2)
    return f"{sexe}{annee}{mois}{dept}{commune}{ordre}{cle}"


def generate_patients(n=50):
    patients = []
    for _ in range(n):
        patients.append({
            "nom": fake.last_name(),
            "prenom": fake.first_name(),
            "date_naissance": fake.date_of_birth(minimum_age=18, maximum_age=90).strftime("%d/%m/%Y"),
            "nir": generate_nir(),
            "adresse": fake.address().replace("\n", ", "),
            "medecin_traitant": random.choice(MEDECINS)
        })
    return patients


def generate_dossier(patient_id):
    diagnostic = random.choice(DIAGNOSTICS)
    medicament = random.choice(MEDICAMENTS)
    note = random.choice(NOTES_TCIM)
    return {
        "patient_id": patient_id,
        "diagnostic": diagnostic,
        "medicaments": medicament,
        "notes": note,
        "sensitivity_level": random.choice(["low", "medium", "high"])
    }


def generate_personnel():
    """Génère le personnel : 1 admin, 6 médecins, 9 infirmiers (sans patient_id)."""
    utilisateurs = []
    # 1 administrateur
    utilisateurs.append({
        "nom": fake.last_name(), "prenom": fake.first_name(),
        "role": "admin", "username": "admin1", "patient_id": None
    })
    # 6 médecins
    for i in range(6):
        utilisateurs.append({
            "nom": fake.last_name(), "prenom": fake.first_name(),
            "role": "medecin", "username": f"medecin{i+1}", "patient_id": None
        })
    # 9 infirmiers
    for i in range(9):
        utilisateurs.append({
            "nom": fake.last_name(), "prenom": fake.first_name(),
            "role": "infirmier", "username": f"infirmier{i+1}", "patient_id": None
        })
    return utilisateurs


def populate_database():
    print("Initialisation de la base de données...")
    init_db()

    print("Génération du personnel (1 admin, 6 médecins, 9 infirmiers)...")
    for u in generate_personnel():
        insert_utilisateur(u["nom"], u["prenom"], u["role"], u["username"], u["patient_id"])

    print("Génération des 50 patients + dossiers + comptes patients liés...")
    patients = generate_patients(50)
    for i, p in enumerate(patients, start=1):
        patient_id = insert_patient(
            p["nom"], p["prenom"], p["date_naissance"],
            p["nir"], p["adresse"], p["medecin_traitant"]
        )
        dossier = generate_dossier(patient_id)
        insert_dossier(
            dossier["patient_id"], dossier["diagnostic"],
            dossier["medicaments"], dossier["notes"],
            dossier["sensitivity_level"]
        )
        # Chaque patient a son propre compte, lié à son dossier
        insert_utilisateur(
            p["nom"], p["prenom"], "patient",
            f"patient{i}", patient_id
        )

    print("Base de données peuplée : 66 comptes (1 admin, 6 médecins, 9 infirmiers, 50 patients).")


if __name__ == "__main__":
    populate_database()