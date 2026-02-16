/**
 * Navigate back in browser history
 * @param {string} fallbackUrl - Internal URL used as fallback
 */
function goBackOrFallback(fallbackUrl = "/"){
    const hasHistory = window.history.length > 1;
    const referrer = document.referrer || "";

    let isSameOriginReferrer = false;
    
    try {
        isSameOriginReferrer = !!referrer && new URL(referrer).origin === window.location.origin;
    }catch (error) {
        isSameOriginReferrer = false;
    }

    // Use browser back only when it is safe
    if (hasHistory && isSameOriginReferrer) {
        window.history.back();
        return;
    }

    // Fallback to a known page if no valid history exists.
    window.location.assign(fallbackUrl);
}