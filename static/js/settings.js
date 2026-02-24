// static/js/settings.js
(function () {
  function byId(id) { return document.getElementById(id); }

  const themeSelect = byId("themeSelect");
  const fontSelect  = byId("fontSelect");

  // If someone hits /settings before ui_prefs.js loads, fail safely.
  if (!themeSelect || !fontSelect) return;

  // init dropdowns from saved prefs
  if (window.getThemePref) themeSelect.value = window.getThemePref();
  if (window.getFontPref)  fontSelect.value  = window.getFontPref();

  themeSelect.addEventListener("change", () => {
    if (window.setThemePref) window.setThemePref(themeSelect.value);
    if (window.applyPrefs) window.applyPrefs();
  });

  fontSelect.addEventListener("change", () => {
    if (window.setFontPref) window.setFontPref(fontSelect.value);
    if (window.applyPrefs) window.applyPrefs();
  });
})();