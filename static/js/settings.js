// static/js/settings.js
(function () {
  function byId(id) { return document.getElementById(id); }

  const themeSelect = byId("themeSelect");
  const fontSelect  = byId("fontSelect");
  if (!themeSelect || !fontSelect) return;

  const THEME_KEY = "ui_theme";
  const FONT_KEY  = "ui_font_size";

  function safeGet(key, fallback) {
    try {
      const v = localStorage.getItem(key);
      return v === null ? fallback : v;
    } catch (e) { return fallback; }
  }

  function safeSet(key, value) {
    try { localStorage.setItem(key, value); } catch (e) {}
  }

  // init dropdown values
  themeSelect.value = (window.getThemePref ? window.getThemePref() : safeGet(THEME_KEY, "system"));
  fontSelect.value  = (window.getFontPref  ? window.getFontPref()  : safeGet(FONT_KEY, "md"));

  function apply() {
    if (window.applyPrefs) window.applyPrefs();
  }

  themeSelect.addEventListener("change", () => {
    const v = themeSelect.value;
    if (window.setThemePref) window.setThemePref(v);
    else safeSet(THEME_KEY, v);
    apply();
  });

  fontSelect.addEventListener("change", () => {
    const v = fontSelect.value;
    if (window.setFontPref) window.setFontPref(v);
    else safeSet(FONT_KEY, v);
    apply();
  });
})();