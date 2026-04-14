window.showAppFeedback = function (message, kind = "success") {
    if (!message) return;

    const container = document.getElementById("app-feedback-container");
    if (!container) return;

    const toast = document.createElement("div");
    toast.className = `app-feedback-toast app-feedback-${kind}`;
    toast.setAttribute("role", kind === "error" ? "alert" : "status");
    toast.setAttribute("aria-live", kind === "error" ? "assertive" : "polite");
    toast.setAttribute("aria-atomic", "true");
    toast.textContent = message;

    container.appendChild(toast);

    setTimeout(() => {
        toast.remove();
    }, 3500);
};

window.readJsonSafely = async function (response) {
    try {
        return await response.json();
    } catch {
        return {};
    }
};