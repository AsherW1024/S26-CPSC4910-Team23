const productRows = document.querySelectorAll(".product-row");

for (const row of productRows) {
	row.addEventListener("click", showProductPopup);
	row.addEventListener("keydown", (event) => {
		if (event.key === "Enter" || event.key === " ") {
			event.preventDefault();
			showProductPopup({ target: row });
		}
	});
}

async function showProductPopup(event) {
	const row = event.target.closest(".product-row");
	if (!row) return;

	const productID = row.dataset.productId;
	const popupDiv = document.getElementById("popup-overlay-bg");
	const response = await fetch(`/product/${productID}`);

	if (response.ok) {
		const popupHtml = await response.text();
		popupDiv.innerHTML = popupHtml;
		popupDiv.hidden = false;
		const popupScript = document.createElement("script");
		popupScript.src = "/static/js/product_popup.js";
		document.body.appendChild(popupScript);
	}
}