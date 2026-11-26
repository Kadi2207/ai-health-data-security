/*
 * TCIM : traduction À L'AFFICHAGE des logs d'audit et des alertes.
 *
 * Les logs et les alertes restent stockés en français dans la base :
 * le moteur de détection (security_monitor) s'appuie sur ces libellés
 * (ex. « connexion », « 2FA »). Rien n'est réécrit côté serveur.
 * Ce module ne fait que proposer une version anglaise au moment de
 * l'affichage, quand l'interface est en anglais.
 *
 *   MSPI18N.log(texte, lang)     action ou ressource d'un log d'audit
 *   MSPI18N.alerte(texte, lang)  message d'une alerte de sécurité
 *   MSPI18N.resultat(r, lang)    « accordé » / « refusé »
 *
 * Règles :
 *   - texte inconnu  -> renvoyé tel quel (jamais de perte d'information) ;
 *   - parties libres (noms de comptes, motif saisi par l'admin) -> conservées
 *     telles quelles, seuls les libellés fixes sont traduits ;
 *   - le résultat est du TEXTE : il doit toujours passer par MSPUI.esc()
 *     avant une insertion HTML.
 */
(function () {
    "use strict";

    // Recherche dans une table de correspondance, sans remonter les propriétés
    // héritées (un texte « constructor » ne doit pas renvoyer une fonction).
    function own(table, cle, defaut) {
        return Object.prototype.hasOwnProperty.call(table, cle) ? table[cle] : defaut;
    }

    // ── Libellés fixes (correspondance exacte) ───────────────────────────────
    var EXACT = {
        // Actions
        "Connexion — mot de passe validé": "Login — password verified",
        "Connexion 2FA réussie": "2FA login successful",
        "Échec connexion — mot de passe incorrect": "Login failed — incorrect password",
        "Échec connexion 2FA": "2FA login failed",
        "Tentative connexion sur compte bloqué": "Login attempt on a blocked account",
        "Échec 2FA — mot de passe non validé au préalable": "2FA failed — password not verified beforehand",
        "Tentative 2FA sur compte bloqué": "2FA attempt on a blocked account",
        "Changement de mot de passe (première connexion)": "Password change (first login)",
        "Consultation de son propre dossier": "Viewed own medical record",
        "Tentative de création de dossier": "Attempt to create a record",
        "Tentative d'ajout d'entrée médicale": "Attempt to add a medical entry",
        "Déblocage de secours (break-glass) via accès serveur direct": "Emergency unblock (break-glass) via direct server access",
        // Appareil de confiance (lot 5)
        "Connexion — appareil de confiance (double authentification non demandée)": "Login — trusted device (two-factor authentication skipped)",
        "Appareil de confiance : cookie falsifié ou invalide — double authentification exigée": "Trusted device: forged or invalid cookie — two-factor authentication required",
        "Appareil de confiance non reconnu — double authentification exigée": "Unrecognized trusted device — two-factor authentication required",
        "Appareil de confiance expiré — double authentification exigée": "Trusted device expired — two-factor authentication required",
        "Appareil de confiance révoqué — double authentification exigée": "Trusted device revoked — two-factor authentication required",
        "Enregistrement d'appareil de confiance refusé (session ouverte sans double authentification)": "Trusted device registration denied (session opened without two-factor authentication)",

        // Ressources
        "Accès au système": "System access",
        "Dossier Médical": "Medical record",
        "Compte utilisateur": "User account",
        "tentative_action_privilegiee": "Privileged action attempt",
        "Création dossier refusée (rôle non autorisé)": "Record creation denied (unauthorized role)",
        "Ajout refusé (rôle non autorisé)": "Entry denied (unauthorized role)",
        "Accès de secours hors-ligne": "Offline emergency access",
        "Appareil de confiance": "Trusted device"
    };

    // Catégories de déblocage (liste contrôlée côté serveur)
    var CATEGORIES = {
        "Identité vérifiée": "Identity verified",
        "Incident de sécurité traité": "Security incident handled",
        "Test de sécurité": "Security test"
    };

    function categorie(c) {
        return own(CATEGORIES, c, c);
    }

    // ── Libellés à variables (expressions régulières ancrées) ────────────────
    // Chaque motif reconnaît une phrase complète ; les parties variables
    // (identifiants, compteurs, noms de comptes) sont recopiées sans changement.
    var MOTIFS = [
        // Actions
        [/^Consultation du dossier patient #(\d+)$/, function (m) { return "Viewed patient record #" + m[1]; }],
        [/^Ajout d'une entrée au dossier patient #(\d+)$/, function (m) { return "Entry added to patient record #" + m[1]; }],
        [/^Création d'un dossier médical \(patient_id=(\d+)\)$/, function (m) { return "Medical record created (patient_id=" + m[1] + ")"; }],
        [/^Tentative de déblocage de ([\s\S]*) — mot de passe admin incorrect$/, function (m) { return "Unblock attempt for " + m[1] + " — incorrect admin password"; }],
        [/^Déblocage du compte ([\s\S]+)$/, function (m) { return "Account unblocked: " + m[1]; }],
        [/^Appareil de confiance enregistré \((\d+) jours\)$/, function (m) { return "Trusted device registered (" + m[1] + " days)"; }],
        [/^Révocation des appareils de confiance du compte ([\s\S]+) \((\d+)\)$/, function (m) { return "Trusted devices revoked for account " + m[1] + " (" + m[2] + ")"; }],

        // Ressources
        [/^Historique médical · (\d+) entrée\(s\) consultée\(s\)$/, function (m) { return "Medical history · " + m[1] + " entry(ies) viewed"; }],
        [/^Dossier personnel · (\d+) entrée\(s\)$/, function (m) { return "Personal record · " + m[1] + " entry(ies)"; }],
        [/^Entrée médicale #(\d+) · sensibilité : (\w+)$/, function (m) { return "Medical entry #" + m[1] + " · sensitivity: " + m[2]; }],
        [/^Dossier #(\d+) — sensibilité : (\w+)$/, function (m) { return "Record #" + m[1] + " — sensitivity: " + m[2]; }],
        [/^Appareil de confiance · expire le ([\d\- :]+)$/, function (m) { return "Trusted device · expires on " + m[1]; }],
        [/^dossier_id=(\d+) \(dossier d'autrui\)$/, function (m) { return "dossier_id=" + m[1] + " (another patient's record)"; }],
        // Le motif saisi par l'administrateur est conservé tel quel (texte libre)
        [/^Catégorie : ([\s\S]*?) {2}· {2}Motif : ([\s\S]*)$/, function (m) { return "Category: " + categorie(m[1]) + "  ·  Reason: " + m[2]; }],

        // Erreurs renvoyées par le pipeline
        [/^Utilisateur '([\s\S]*)' introuvable\.$/, function (m) { return "User '" + m[1] + "' not found."; }],
        [/^Dossier introuvable pour patient_id=(\d+)$/, function (m) { return "No record found for patient_id=" + m[1]; }]
    ];

    function log(texte, lang) {
        if (lang !== "en" || texte === null || texte === undefined) return texte;
        var s = String(texte);
        var exact = own(EXACT, s, null);
        if (exact !== null) return exact;
        for (var i = 0; i < MOTIFS.length; i++) {
            var m = MOTIFS[i][0].exec(s);
            if (m) return MOTIFS[i][1](m);
        }
        return s;
    }

    // ── Alertes de sécurité ──────────────────────────────────────────────────
    // Format produit par security_monitor : « [GRAVITÉ] Type — détails »
    var GRAVITES = { "CRITIQUE": "CRITICAL", "ÉLEVÉ": "HIGH", "MOYEN": "MEDIUM" };
    var TYPES = {
        "Brute Force": "Brute Force",
        "Password Spray": "Password Spray",
        "Escalade Privileges": "Privilege Escalation",
        "Acces Anormal": "Abnormal Access",
        "2Fa Force": "2FA Brute Force"
    };
    var DETAILS = [
        [/^(\d+) tentatives de connexion échouées en (\d+) min$/, function (m) { return m[1] + " failed login attempts in " + m[2] + " min"; }],
        [/^Password spray détecté : (\d+) comptes visés simultanément$/, function (m) { return "Password spray detected: " + m[1] + " accounts targeted simultaneously"; }],
        [/^(\d+) tentatives d'action non autorisée \(escalade de privilèges\)$/, function (m) { return m[1] + " unauthorized action attempts (privilege escalation)"; }],
        [/^Volume d'accès anormal : (\d+) actions en (\d+) min$/, function (m) { return "Abnormal access volume: " + m[1] + " actions in " + m[2] + " min"; }]
    ];

    function details(d) {
        for (var i = 0; i < DETAILS.length; i++) {
            var m = DETAILS[i][0].exec(d);
            if (m) return DETAILS[i][1](m);
        }
        return d;
    }

    function alerte(texte, lang) {
        if (lang !== "en" || texte === null || texte === undefined) return texte;
        var s = String(texte);
        var m = /^\[([^\]]+)\] ([\s\S]+?) — ([\s\S]*)$/.exec(s);
        if (!m) return s;
        var gravite = own(GRAVITES, m[1], m[1]);
        var type = own(TYPES, m[2], m[2]);
        return "[" + gravite + "] " + type + " — " + details(m[3]);
    }

    // ── Résultat d'un accès ──────────────────────────────────────────────────
    var RESULTATS = { "accordé": "granted", "refusé": "denied" };

    function resultat(r, lang) {
        if (lang !== "en" || r === null || r === undefined) return r;
        return own(RESULTATS, r, r);
    }

    window.MSPI18N = { log: log, alerte: alerte, resultat: resultat };
})();
