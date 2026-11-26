/*
 * TCIM : gestion du thème clair / sombre.
 *
 * Ce script est chargé de façon synchrone dans le <head> de chaque page,
 * AVANT la feuille de style : l'attribut data-theme est posé sur <html>
 * avant le premier rendu, ce qui évite tout flash de thème.
 *
 * Priorité : choix mémorisé (localStorage) > préférence du système > clair.
 * Un événement "msp:themechange" est émis à chaque bascule, pour que les
 * composants dessinés en JavaScript (graphiques) puissent se mettre à jour.
 */
(function () {
    "use strict";

    var STORAGE_KEY = "msp-theme";
    var root = document.documentElement;
    var media = window.matchMedia ? window.matchMedia("(prefers-color-scheme: dark)") : null;

    function readStored() {
        try {
            var value = window.localStorage.getItem(STORAGE_KEY);
            return value === "dark" || value === "light" ? value : null;
        } catch (e) {
            return null; // navigation privée ou stockage bloqué
        }
    }

    function writeStored(theme) {
        try {
            window.localStorage.setItem(STORAGE_KEY, theme);
        } catch (e) {
            /* le thème reste appliqué pour la page courante */
        }
    }

    function systemTheme() {
        return media && media.matches ? "dark" : "light";
    }

    function current() {
        return root.getAttribute("data-theme") === "dark" ? "dark" : "light";
    }

    function syncToggles(theme) {
        var buttons = document.querySelectorAll("[data-theme-toggle]");
        for (var i = 0; i < buttons.length; i++) {
            buttons[i].setAttribute("aria-pressed", theme === "dark" ? "true" : "false");
        }
    }

    function apply(theme, notify) {
        root.setAttribute("data-theme", theme);
        syncToggles(theme);
        if (notify) {
            var event;
            try {
                event = new CustomEvent("msp:themechange", { detail: { theme: theme } });
            } catch (e) {
                event = document.createEvent("CustomEvent");
                event.initCustomEvent("msp:themechange", false, false, { theme: theme });
            }
            document.dispatchEvent(event);
        }
    }

    function toggle() {
        var next = current() === "dark" ? "light" : "dark";
        writeStored(next);
        apply(next, true);
    }

    // 1. Application immédiate, avant le rendu
    apply(readStored() || systemTheme(), false);

    // 2. Suivre le système tant que l'utilisateur n'a pas fait de choix explicite
    if (media) {
        var onSystemChange = function () {
            if (!readStored()) {
                apply(systemTheme(), true);
            }
        };
        if (media.addEventListener) {
            media.addEventListener("change", onSystemChange);
        } else if (media.addListener) {
            media.addListener(onSystemChange);
        }
    }

    // 3. Brancher les boutons de bascule une fois le DOM prêt
    document.addEventListener("DOMContentLoaded", function () {
        var buttons = document.querySelectorAll("[data-theme-toggle]");
        for (var i = 0; i < buttons.length; i++) {
            buttons[i].addEventListener("click", toggle);
        }
        syncToggles(current());
    });

    // 4. Synchroniser les autres onglets ouverts
    window.addEventListener("storage", function (e) {
        if (e.key === STORAGE_KEY && (e.newValue === "dark" || e.newValue === "light")) {
            apply(e.newValue, true);
        }
    });

    window.MSPTheme = { current: current, toggle: toggle };
})();
