/*
 * TCIM : utilitaires d'interface partagés par toutes les pages.
 *
 *   MSPUI.esc(valeur)            échappe une valeur avant insertion HTML (anti-XSS)
 *   MSPUI.withBusy(bouton, fn)   anti-double-clic : bouton désactivé pendant la requête
 *   MSPToast.show({...})         notification temporaire en haut à droite
 *
 * Présentation uniquement : aucune logique métier ici.
 */
(function () {
    "use strict";

    // ── Échappement HTML ─────────────────────────────────────────────────────
    // Toute donnée venant du serveur (noms, diagnostics, messages, logs...)
    // passe par esc() avant d'être insérée via innerHTML ou un gabarit.
    var REMPLACEMENTS = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;", "`": "&#96;" };

    function esc(valeur) {
        if (valeur === null || valeur === undefined) return "";
        return String(valeur).replace(/[&<>"'`]/g, function (c) { return REMPLACEMENTS[c]; });
    }

    // ── Anti-double-clic ─────────────────────────────────────────────────────
    // Désactive le bouton et affiche un indicateur pendant l'exécution de fn.
    // Un second clic pendant la requête est ignoré. Le bouton est rétabli
    // dans tous les cas (succès, refus, erreur réseau).
    function withBusy(bouton, fn) {
        if (bouton && bouton.getAttribute("aria-busy") === "true") {
            return Promise.resolve();
        }
        var etaitDesactive = bouton ? bouton.disabled : false;
        var spinner = null;
        if (bouton) {
            bouton.disabled = true;
            bouton.setAttribute("aria-busy", "true");
            bouton.classList.add("is-loading");
            spinner = document.createElement("span");
            spinner.className = "spinner spinner--btn";
            spinner.setAttribute("aria-hidden", "true");
            bouton.insertBefore(spinner, bouton.firstChild);
        }
        var fin = function () {
            if (!bouton) return;
            bouton.disabled = etaitDesactive;
            bouton.removeAttribute("aria-busy");
            bouton.classList.remove("is-loading");
            if (spinner && spinner.parentNode) spinner.parentNode.removeChild(spinner);
        };
        var resultat;
        try {
            resultat = Promise.resolve(fn());
        } catch (e) {
            fin();
            return Promise.reject(e);
        }
        return resultat.then(function (v) { fin(); return v; }, function (e) { fin(); throw e; });
    }

    // ── Notifications (toasts) ───────────────────────────────────────────────
    var ICONES = {
        success: '<path d="M20 6L9 17l-5-5"/>',
        error: '<circle cx="12" cy="12" r="10"/><path d="M15 9l-6 6M9 9l6 6"/>',
        warning: '<path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><path d="M12 9v4M12 17h.01"/>',
        info: '<circle cx="12" cy="12" r="10"/><path d="M12 16v-4M12 8h.01"/>'
    };
    var DUREES = { success: 4500, info: 5000, warning: 6500, error: 8000 };
    var LIBELLE_FERMER = { fr: "Fermer la notification", en: "Dismiss notification" };

    function region() {
        var r = document.getElementById("toast-region");
        if (!r) {
            r = document.createElement("div");
            r.id = "toast-region";
            r.className = "toast-region";
            r.setAttribute("aria-live", "polite");
            r.setAttribute("aria-relevant", "additions");
            document.body.appendChild(r);
        }
        return r;
    }

    function fermer(toast) {
        if (!toast || toast.classList.contains("is-leaving")) return;
        toast.classList.add("is-leaving");
        var retirer = function () { if (toast.parentNode) toast.parentNode.removeChild(toast); };
        toast.addEventListener("animationend", retirer);
        setTimeout(retirer, 400); // filet de sécurité si les animations sont désactivées
    }

    /**
     * Affiche une notification.
     * @param {Object} o  { type: "success"|"error"|"warning"|"info", title, message, duration }
     * Les textes sont insérés via textContent : aucun risque d'injection.
     */
    function show(o) {
        o = o || {};
        var type = ICONES[o.type] ? o.type : "info";
        var lang = (document.documentElement.lang || "fr").slice(0, 2);

        var toast = document.createElement("div");
        toast.className = "toast toast--" + type;
        toast.setAttribute("role", type === "error" || type === "warning" ? "alert" : "status");

        var icone = document.createElementNS("http://www.w3.org/2000/svg", "svg");
        icone.setAttribute("viewBox", "0 0 24 24");
        icone.setAttribute("class", "icon toast__icon");
        icone.setAttribute("aria-hidden", "true");
        icone.innerHTML = ICONES[type]; // contenu statique, défini ci-dessus

        var corps = document.createElement("div");
        corps.className = "toast__body";
        if (o.title) {
            var titre = document.createElement("p");
            titre.className = "toast__title";
            titre.textContent = o.title;
            corps.appendChild(titre);
        }
        if (o.message) {
            var texte = document.createElement("p");
            texte.className = "toast__message";
            texte.textContent = o.message;
            corps.appendChild(texte);
        }

        var bouton = document.createElement("button");
        bouton.type = "button";
        bouton.className = "toast__close";
        bouton.setAttribute("aria-label", LIBELLE_FERMER[lang] || LIBELLE_FERMER.fr);
        bouton.innerHTML = '<svg class="icon" viewBox="0 0 24 24" aria-hidden="true"><path d="M18 6L6 18M6 6l12 12"/></svg>';
        bouton.addEventListener("click", function () { fermer(toast); });

        toast.appendChild(icone);
        toast.appendChild(corps);
        toast.appendChild(bouton);

        var r = region();
        r.appendChild(toast);
        // Au plus 4 notifications visibles : on retire les plus anciennes
        while (r.children.length > 4) r.removeChild(r.firstChild);

        // Disparition automatique, suspendue au survol et au focus
        var duree = o.duration || DUREES[type];
        var minuteur = setTimeout(function () { fermer(toast); }, duree);
        var pause = function () { clearTimeout(minuteur); };
        var reprise = function () { minuteur = setTimeout(function () { fermer(toast); }, 2500); };
        toast.addEventListener("mouseenter", pause);
        toast.addEventListener("mouseleave", reprise);
        toast.addEventListener("focusin", pause);
        toast.addEventListener("focusout", reprise);

        return toast;
    }

    window.MSPUI = { esc: esc, withBusy: withBusy };
    window.MSPToast = { show: show };
})();
