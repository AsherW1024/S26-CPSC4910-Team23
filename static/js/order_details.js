const productRows = document.querySelectorAll(".product-row");
for (const row of productRows) {
	row.addEventListener("click", showProductPopup);
}

async function showProductPopup(event) {
	//dont show popup if user was interacting with a button
	if (event.target.tagName === "BUTTON") {return}
	productID = event.target.closest(".product-row").dataset.productId;
	popupDiv = document.getElementById("popup-overlay-bg");
	response = await fetch(`/product/${productID}`);
	if (response.ok) {
		popupHtml = await response.text();
		popupDiv.innerHTML = popupHtml;
		popupDiv.hidden = false;
		const popupScript = document.createElement("script");
		popupScript.src = "/static/js/product_popup.js";
		document.body.appendChild(popupScript);
	}
}