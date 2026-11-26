-- Projet TCIM — Schéma PostgreSQL

DROP TABLE IF EXISTS appareils_confiance CASCADE;
DROP TABLE IF EXISTS alertes CASCADE;
DROP TABLE IF EXISTS audit_logs CASCADE;
DROP TABLE IF EXISTS dossiers_medicaux CASCADE;
DROP TABLE IF EXISTS utilisateurs CASCADE;
DROP TABLE IF EXISTS patients CASCADE;

CREATE TABLE utilisateurs (
    id SERIAL PRIMARY KEY,
    nom TEXT NOT NULL,
    prenom TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('medecin', 'patient', 'admin', 'infirmier')),
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT,
    otp_secret TEXT,
    patient_id INTEGER,
    doit_changer_mdp INTEGER DEFAULT 1,
    est_bloque INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE patients (
    id SERIAL PRIMARY KEY,
    nom TEXT NOT NULL,
    prenom TEXT NOT NULL,
    date_naissance TEXT NOT NULL,
    nir TEXT NOT NULL,
    adresse TEXT,
    medecin_traitant TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

ALTER TABLE utilisateurs ADD CONSTRAINT fk_utilisateur_patient
    FOREIGN KEY (patient_id) REFERENCES patients(id);

CREATE TABLE dossiers_medicaux (
    id SERIAL PRIMARY KEY,
    patient_id INTEGER NOT NULL,
    diagnostic TEXT,
    medicaments TEXT,
    notes TEXT,
    medecin_auteur TEXT,
    is_encrypted INTEGER DEFAULT 0,
    sensitivity_level TEXT DEFAULT 'low' CHECK(sensitivity_level IN ('low', 'medium', 'high')),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (patient_id) REFERENCES patients(id)
);
DROP TABLE IF EXISTS entrees_dossier CASCADE;
CREATE TABLE entrees_dossier (
    id SERIAL PRIMARY KEY,
    patient_id INTEGER NOT NULL,
    diagnostic TEXT,
    medicaments TEXT,
    notes TEXT,
    medecin_auteur TEXT NOT NULL,
    is_encrypted INTEGER DEFAULT 0,
    sensitivity_level TEXT DEFAULT 'low' CHECK(sensitivity_level IN ('low', 'medium', 'high')),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (patient_id) REFERENCES patients(id)
);

CREATE TABLE audit_logs (
    id SERIAL PRIMARY KEY,
    utilisateur_id TEXT NOT NULL,
    action TEXT NOT NULL,
    ressource TEXT NOT NULL DEFAULT 'Dossier Médical',
    resultat TEXT NOT NULL CHECK(resultat IN ('accordé', 'refusé')),
    timestamp TEXT NOT NULL
);

CREATE TABLE alertes (
    id SERIAL PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    message TEXT NOT NULL,
    timestamp TEXT NOT NULL
);

-- Appareils de confiance (2FA allégée, mot de passe toujours exigé).
-- Seule l'empreinte SHA-256 du jeton est stockée ; expiration fixe de 30 jours.
CREATE TABLE appareils_confiance (
    id SERIAL PRIMARY KEY,
    username TEXT NOT NULL REFERENCES utilisateurs(username) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    libelle TEXT,
    created_at TIMESTAMP NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    last_used_at TIMESTAMP,
    revoked_at TIMESTAMP
);
CREATE INDEX idx_appareils_confiance_username ON appareils_confiance (username);