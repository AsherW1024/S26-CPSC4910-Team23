let previousFocusedElement = document.activeElement;

function getPopup() {
	return document.getElementById("popup-content-div");
}

function closePopup() {
	const popupEl = document.getElementById("popup-overlay-bg");
	if (!popupEl) return;
	popupEl.innerHTML = "";
	popupEl.hidden = true;
	if (previousFocusedElement) previousFocusedElement.focus();
}

function trapFocus(event) {
	const popup = getPopup();
	if (!popup || event.key !== "Tab") return;

	const focusable = popup.querySelectorAll(
		'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
	);

	if (!focusable.length) return;

	const first = focusable[0];
	const last = focusable[focusable.length - 1];

	if (event.shiftKey && document.activeElement === first) {
		event.preventDefault();
		last.focus();
	} else if (!event.shiftKey && document.activeElement === last) {
		event.preventDefault();
		first.focus();
	}
}

function attachPopupAccessibility() {
	const popup = getPopup();
	const closeButton = document.getElementById("popup-close");
	const copyButton = document.querySelector(".popup-share-button");
	const feedback = document.getElementById("popup-copy-feedback");

	if (closeButton) {
		closeButton.addEventListener("click", closePopup);
		closeButton.focus();
	}

	document.addEventListener("keydown", handleKeydown);
	if (copyButton) {
		copyButton.addEventListener("click", async () => {
			const productId = copyButton.dataset.productId;
			const productUrl = `${window.location.origin}/product/${productId}`;
			try {
				await navigator.clipboard.writeText(productUrl);
				if (feedback) feedback.textContent = "Link copied.";
			} catch {
				if (feedback) feedback.textContent = "Copy failed.";
			}
			setTimeout(() => {
				if (feedback) feedback.textContent = "";
			}, 2000);
		});
	}
}

function handleKeydown(event) {
	if (event.key === "Escape") {
		closePopup();
		return;
	}
	trapFocus(event);
}

document.addEventListener("DOMContentLoaded", attachPopupAccessibility);
attachPopupAccessibility();