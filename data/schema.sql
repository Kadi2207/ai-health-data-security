-- Projet TCIM — Schéma de la base de données SQLite

CREATE TABLE IF NOT EXISTS utilisateurs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nom TEXT NOT NULL,
    prenom TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('medecin', 'patient', 'admin', 'infirmier')),
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT,
    otp_secret TEXT,
    patient_id INTEGER,
    doit_changer_mdp INTEGER DEFAULT 1,
    est_bloque INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (patient_id) REFERENCES patients(id)
);

CREATE TABLE IF NOT EXISTS patients (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nom TEXT NOT NULL,
    prenom TEXT NOT NULL,
    date_naissance TEXT NOT NULL,
    nir TEXT NOT NULL,
    adresse TEXT,
    medecin_traitant TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS dossiers_medicaux (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    patient_id INTEGER NOT NULL,
    diagnostic TEXT,
    medicaments TEXT,
    notes TEXT,
    is_encrypted INTEGER DEFAULT 0,
    sensitivity_level TEXT DEFAULT 'low' CHECK(sensitivity_level IN ('low', 'medium', 'high')),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (patient_id) REFERENCES patients(id)
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    utilisateur_id TEXT NOT NULL,
    action TEXT NOT NULL,
    ressource TEXT NOT NULL DEFAULT 'Dossier Médical',
    resultat TEXT NOT NULL CHECK(resultat IN ('accordé', 'refusé')),
    timestamp TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS alertes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    message TEXT NOT NULL,
    timestamp TEXT NOT NULL
);