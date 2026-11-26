import os
import pickle
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import accuracy_score, classification_report
import numpy as np

EXEMPLES_SENSIBLES = [
    "Patient atteint de diabète de type 2 sous Metformine 500mg",
    "Diagnostic : cancer du poumon stade 3, chimiothérapie en cours",
    "NIR : 178054412345678, né le 12/05/1978",
    "Traitement antidépresseur Sertraline 50mg prescrit",
    "Patient séropositif VIH sous Ténofovir 300mg",
    "Insuffisance cardiaque sévère, Furosémide 40mg quotidien",
    "Schizophrénie diagnostiquée, Rispéridone 2mg",
    "Tuberculose pulmonaire active, Isoniazide 300mg",
    "Alzheimer débutant, Donépézil 10mg prescrit",
    "Dépression sévère avec idées suicidaires, hospitalisation",
    "Épilepsie résistante, Valproate 500mg",
    "Cancer du sein métastatique, chimiothérapie Méthotrexate",
    "Patient toxicomane sous traitement substitution Morphine",
    "Hépatite C chronique, Ribavirine 200mg",
    "Trouble bipolaire, Lithium 400mg prescrit",
    "Parkinson stade 2, Lévodopa 250mg trois fois par jour",
    "Insuffisance rénale chronique, dialyse deux fois par semaine",
    "Infection VIH contrôlée, charge virale indétectable",
    "Antécédents psychiatriques, hospitalisation en 2022",
    "Ordonnance Alprazolam 0.5mg, traitement anxiété",
    "Groupe sanguin O+, allergie pénicilline documentée",
    "Adresse : 12 rue des Lilas 75010 Paris, né le 03/07/1965",
    "Mutuelle MGEN, numéro adhérent 123456789",
    "Dossier patient confidentiel, médecin traitant Dr. Martin",
    "Diagnostic fibromyalgie, Prégabaline 75mg",
    "Arthrite rhumatoïde sévère, Méthotrexate 15mg hebdomadaire",
    "Ostéoporose avancée, Calcium 1000mg et vitamine D",
    "Asthme sévère, Salbutamol 100mcg en cas de crise",
    "Hypertension artérielle, Amlodipine 5mg quotidien",
    "Corticoïde Prednisone 20mg prescrit, suivi endocrinologue",
    "Patient sous anticoagulant Warfarine, INR à surveiller",
    "Prescription morphinique, douleurs chroniques sévères",
    "Données sensibles : diagnostic psychiatrique, traitement en cours",
    "NIR 278126754321098, adresse confidentielle",
    "Anamnèse : antécédents familiaux cancer colorectal",
    "Dossier médical confidentiel, accès restreint médecin",
    "Traitement substitution opiacé Méthadone 40mg",
    "Bilan sanguin : glycémie 2.8g/L, diabète déséquilibré",
    "Patient sous chimiothérapie, immunodéprimé sévère",
    "Diagnostic : trouble de la personnalité borderline",
    "Prescription stupéfiant, ordonnance sécurisée requise",
    "Antécédent AVC ischémique, traitement anticoagulant",
    "Infection urinaire récidivante, Ciprofloxacine 500mg",
    "Allergie sévère latex et pénicilline documentée",
    "Suivi psychiatrique mensuel, traitement neuroleptique",
    "Résultats biopsie : lésion maligne confirmée",
    "Prescription anxiolytique benzodiazépine, dépendance signalée",
    "Dossier oncologie : rémission partielle après 6 cures",
    "Patient mineur 16 ans, consentement parental requis",
    "Séropositivité confirmée, suivi infectiologue mensuel",
    "Numéro sécurité sociale 1780544123456, patient hospitalisé",
    "Antidépresseur Venlafaxine 75mg, tentative suicide antérieure",
    "Greffe rénale 2021, traitement immunosuppresseur Tacrolimus",
    "Diagnostic sclérose en plaques, Interféron bêta prescrit",
    "Lupus érythémateux systémique, Hydroxychloroquine 200mg",
    "Maladie de Crohn active, Infliximab perfusion mensuelle",
    "Trouble anxieux généralisé, Escitalopram 10mg",
    "Addiction alcool sévère, sevrage médicalisé Diazépam",
    "Psychose aiguë, hospitalisation sous contrainte",
    "Cancer de la prostate, hormonothérapie Leuproréline",
    "Insuffisance hépatique, cirrhose stade Child C",
    "VIH stade SIDA, prophylaxie Cotrimoxazole",
    "Diabète insulinodépendant, pompe à insuline",
    "Patiente enceinte diabétique, insuline Glargine",
    "Données confidentielles patient psychiatrique",
    "NIR 185034512398765 date naissance 15/03/1985",
    "Antécédents violences conjugales, suivi psychologique",
    "Séropositivité hépatite B, Ténofovir disoproxil",
    "Traitement opiacé fort, surveillance addiction requise",
    "Allergie anaphylactique abeilles, adrénaline auto-injecteur",
    "Dialyse rénale trois fois semaine, insuffisance terminale",
    "Mélanome métastatique, immunothérapie Pembrolizumab",
    "Transplantation cardiaque 2020, Ciclosporine anti-rejet",
    "Trouble déficit attention adulte, Méthylphénidate prescrit",
    "Anorexie mentale sévère, hospitalisation spécialisée",
    "Antécédents abus substances, suivi addictologie",
    "Leucémie aiguë myéloblastique, chimiothérapie intensive",
    "Démence vasculaire avancée, placement envisagé",
    "Hypothyroïdie, Lévothyroxine 100mcg quotidien",
    "Psoriasis sévère, Méthotrexate et photothérapie",
    "Apnée du sommeil sévère, appareillage CPAP",
    "Péricardite récidivante, Colchicine 0.5mg",
    "Patient sans domicile fixe, vulnérabilité sociale",
    "Résultat PCR VIH positif, annonce diagnostic difficile",
    "Cirrhose alcoolique, sevrage alcool en cours",
    "Pneumonie sévère, oxygénothérapie, soins intensifs",
    "Cancer ovaire stade IV, soins palliatifs initiés",
    "Syndrome dépressif post-partum, Sertraline allaitement",
    "Résistance antibiotiques, SARM infection nosocomiale",
    "Trisomie 21, suivi multidisciplinaire spécialisé",
    "Maladie Huntington familiale, suivi neurologique",
    "Pathologie rare Gaucher, traitement enzymatique substitutif",
    "Schizophrénie paranoïde, clozapine surveillance NFS",
    "Méningite bactérienne, hospitalisation urgente réanimation",
    "Sepsis sévère, antibiothérapie large spectre urgente",
    "Dossier VIH confidentiel, partenaires à informer",
    "Addiction héroïne, traitement substitution Buprénorphine",
    "Carcinome hépatocellulaire, éligibilité transplantation",
]

EXEMPLES_NON_SENSIBLES = [
    "Rendez-vous pris pour le mois prochain",
    "Consultation de routine, rien à signaler",
    "Bilan annuel normal, pas d'anomalie détectée",
    "Le patient se porte bien, suivi dans 6 mois",
    "Renouvellement ordonnance vitamines et compléments",
    "Visite de contrôle post-opératoire satisfaisante",
    "Patient en bonne santé générale",
    "Résultats d'analyse dans les normes",
    "Pas de traitement nécessaire pour le moment",
    "Consultation téléphonique, patient rassuré",
    "Prise de tension normale, pas de changement",
    "Bilan lipidique normal",
    "Radiographie thoracique sans anomalie détectée",
    "Pas d'antécédents médicaux significatifs signalés",
    "Consultation de prévention, vaccins à jour",
    "Le suivi est satisfaisant, prochain rendez-vous dans 3 mois",
    "Arrêt de travail trois jours pour grippe saisonnière",
    "Consultation dermatologique, grain de beauté bénin",
    "Ordonnance lunettes, myopie légère stable",
    "Entorse cheville légère, repos et glaçage recommandés",
    "Rhume saisonnier, traitement symptomatique paracétamol",
    "Certificat médical sport, apte sans restriction",
    "Visite médicale travail, apte au poste occupé",
    "Otite moyenne, cure antibiotique courte",
    "Conjonctivite allergique saisonnière, collyre prescrit",
    "Douleur lombaire mécanique, kinésithérapie recommandée",
    "Bilan pré-opératoire normal, intervention programmée",
    "Pas de contre-indication médicale signalée",
    "Patient sportif régulier, bilan cardio normal",
    "Suivi grossesse normal, terme dans 3 semaines",
    "Examen clinique normal, aucune anomalie",
    "Pas d'allergie connue à ce jour",
    "Patient non fumeur, bilan pulmonaire normal",
    "Consultation ORL, audition parfaitement normale",
    "Bilan thyroïdien dans les normes attendues",
    "Pas de traitement médicamenteux en cours",
    "Visite de contrôle annuelle sans particularité",
    "Patient asymptomatique, surveillance simple",
    "Résultats normaux, prochain bilan dans un an",
    "Certificat médical scolaire délivré sans restriction",
    "Pas de symptôme particulier rapporté ce jour",
    "Consultation nutritionnelle, alimentation équilibrée conseillée",
    "Bilan sanguin complet dans les normes",
    "Pas de signe infectieux clinique détecté",
    "Suivi post-vaccination normal sans réaction",
    "Examen ophtalmologique normal, acuité préservée",
    "Pas de traitement médicamenteux requis actuellement",
    "Consultation de contrôle satisfaisante",
    "Patient en bonne forme physique générale",
    "Prochaine consultation programmée dans six mois",
    "Bilan de santé complet satisfaisant pour l'âge",
    "Pas d'antécédent chirurgical notable",
    "Tension artérielle normale, fréquence cardiaque régulière",
    "Poids stable, pas de variation significative",
    "Bilan rénal et hépatique dans les normes",
    "Pas d'anomalie à l'électrocardiogramme de repos",
    "Suivi dentaire régulier, aucune carie détectée",
    "Patient observant, prise médicaments régulière confirmée",
    "Certificat aptitude sport de combat délivré",
    "Bilan hormonal normal pour l'âge du patient",
    "Consultation podologie, aucune pathologie détectée",
    "Pas de douleur chronique rapportée",
    "Sommeil satisfaisant, pas de trouble signalé",
    "Bilan nutritionnel correct, pas de carence",
    "Pas de signe neurologique focal décelé",
    "Vaccination grippe réalisée sans effet secondaire",
    "Bilan ostéodensitométrie normal pour l'âge",
    "Pas de trouble de la vision signalé",
    "Consultation de suivi post-accouchement normale",
    "Développement staturo-pondéral normal pour l'enfant",
    "Pas de syndrome inflammatoire biologique",
    "Cicatrisation satisfaisante post-opératoire",
    "Patient bien hydraté, état général satisfaisant",
    "Pas de symptôme digestif signalé",
    "Bilan allergologique négatif",
    "Examen dermatologique normal, peau saine",
    "Pas de trouble du rythme cardiaque détecté",
    "Consultation prénatale normale semaine 32",
    "Pas de signe d'infection en cours",
    "Bilan de croissance normal pour l'enfant",
    "Pas de traitement en dehors des vitamines",
    "Contrôle tension satisfaisant ce jour",
    "Patient calme et coopératif lors de la consultation",
    "Pas de plainte particulière signalée",
    "Rendez-vous prochain dans 12 mois pour bilan annuel",
    "Pas d'urgence médicale identifiée",
    "Examen gynécologique de routine normal",
    "Bilan sanguin à jeun dans les valeurs normales",
    "Frottis cervical normal, pas de lésion",
    "Mammographie normale, prochain contrôle dans deux ans",
    "Pas de varices ni trouble circulatoire",
    "Consultation médecine générale sans particularité",
    "Pas de signe de déshydratation",
    "Bilan thyroïde normal, pas de modification traitement",
    "Consultation de suivi satisfaisante",
    "Patient autonome, pas d'aide à domicile nécessaire",
    "Pas de trouble cognitif décelé",
    "Bilan préopératoire complet satisfaisant",
    "Pas de signe de récidive décelé",
]

def generate_dataset():
    texts = EXEMPLES_SENSIBLES + EXEMPLES_NON_SENSIBLES
    labels = [1] * len(EXEMPLES_SENSIBLES) + [0] * len(EXEMPLES_NON_SENSIBLES)
    return texts, labels

def train_and_save():
    print("Génération du dataset médical enrichi...")
    texts, labels = generate_dataset()
    print(f"Dataset : {len(texts)} exemples ({sum(labels)} sensibles, {len(labels)-sum(labels)} non sensibles)")

    X_train, X_test, y_train, y_test = train_test_split(
        texts, labels, test_size=0.2, random_state=42, stratify=labels
    )

    print("Entraînement du modèle TF-IDF + Random Forest...")
    pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(
            ngram_range=(1, 2),
            max_features=8000,
            sublinear_tf=True,
            min_df=1
        )),
        ("clf", RandomForestClassifier(
            n_estimators=300,
            max_depth=None,
            min_samples_split=2,
            random_state=42,
            class_weight="balanced"
        ))
    ])

    pipeline.fit(X_train, y_train)
    y_pred = pipeline.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)

    cv_scores = cross_val_score(pipeline, texts, labels, cv=5, scoring="accuracy")

    print(f"\nAccuracy test set     : {accuracy*100:.1f}%")
    print(f"Accuracy cross-val    : {cv_scores.mean()*100:.1f}% (+/- {cv_scores.std()*100:.1f}%)")
    print("\nRapport de classification :")
    print(classification_report(y_test, y_pred,
          target_names=["Non sensible", "Sensible"]))

    model_path = os.path.join(
        os.path.dirname(__file__), "..", "data", "model.pkl"
    )
    with open(model_path, "wb") as f:
        pickle.dump({"pipeline": pipeline, "accuracy": accuracy}, f)

    print(f"Modèle sauvegardé : {model_path}")
    return accuracy

if __name__ == "__main__":
    accuracy = train_and_save()
    print(f"\nModèle prêt — Accuracy : {accuracy*100:.1f}%")