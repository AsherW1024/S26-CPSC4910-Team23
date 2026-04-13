function closePopup() {
	let popupEl = document.getElementById("popup-overlay-bg");
	popupEl.innerHTML = "";
	popupEl.hidden = true;
}

document.getElementById("popup-close").addEventListener("click", closePopup);

function attachCopyProductLinkHandler() {
    const copyButton = document.querySelector(".popup-share-button");
    const feedback = document.getElementById("popup-copy-feedback");

    if (!copyButton) {
        return;
    }

    copyButton.addEventListener("click", async () => {
        const productId = copyButton.dataset.productId;
        const productUrl = `${window.location.origin}/product/${productId}`;

        try {
            await navigator.clipboard.writeText(productUrl);
            if (feedback) {
                feedback.textContent = "Link copied!";
            }
        } catch (error) {
            console.error("Failed to copy product link:", error);
            if (feedback) {
                feedback.textContent = "Copy failed.";
            }
        }

        if (feedback) {
            setTimeout(() => {
                feedback.textContent = "";
            }, 2000);
        }
    });
}

document.addEventListener("click", (event) => {
    if (event.target && event.target.id === "popup-close") {
        return;
    }

    if (event.target && event.target.classList.contains("popup-share-button")) {
        return;
    }
});

document.addEventListener("DOMContentLoaded", attachCopyProductLinkHandler);