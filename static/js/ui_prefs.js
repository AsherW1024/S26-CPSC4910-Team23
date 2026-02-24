// static/js/ui_prefs.js
(function () {
  const THEME_KEY = "ui_theme";     // "system" | "light" | "dark"
  const FONT_KEY  = "ui_font_size"; // "sm" | "md" | "lg" | "xl"

  function safeGet(key, fallback) {
    try {
      const v = localStorage.getItem(key);
      return v === null ? fallback : v;
    } catch (e) {
      return fallback;
    }
  }

  function safeSet(key, value) {
    try {
      localStorage.setItem(key, value);
    } catch (e) {
      // ignore (private mode / blocked storage)
    }
  }

  window.getThemePref = function () {
    return safeGet(THEME_KEY, "system");
  };

  window.setThemePref = function (value) {
    const v = (value === "light" || value === "dark" || value === "system") ? value : "system";
    safeSet(THEME_KEY, v);
    return v;
  };

  window.getFontPref = function () {
    return safeGet(FONT_KEY, "md");
  };

  window.setFontPref = function (value) {
    const allowed = new Set(["sm", "md", "lg", "xl"]);
    const v = allowed.has(value) ? value : "md";
    safeSet(FONT_KEY, v);
    return v;
  };

  function computeTheme(pref) {
    if (pref === "light" || pref === "dark") return pref;

    // system
    if (window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches) {
      return "dark";
    }
    return "light";
  }

  window.applyPrefs = function () {
    const themePref = window.getThemePref();
    const fontPref  = window.getFontPref();

    const theme = computeTheme(themePref);
    document.documentElement.dataset.theme = theme;
    document.documentElement.dataset.themePref = themePref;
    document.documentElement.dataset.font = fontPref;
  };

  // apply ASAP on load
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", window.applyPrefs);
  } else {
    window.applyPrefs();
  }

  // live update if system theme changes while using "system"
  if (window.matchMedia) {
    const mq = window.matchMedia("(prefers-color-scheme: dark)");
    const handler = () => {
      if (window.getThemePref() === "system") window.applyPrefs();
    };
    if (mq.addEventListener) mq.addEventListener("change", handler);
    else if (mq.addListener) mq.addListener(handler);
  }
})();