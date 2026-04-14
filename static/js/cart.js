const incrementButtons = document.querySelectorAll(".increment-button");
const decrementButtons = document.querySelectorAll(".decrement-button");
const removeButtons = document.querySelectorAll(".remove-cart-item");
const productRows = document.querySelectorAll(".product-row");

for (const row of productRows) {
	row.addEventListener("click", showProductPopup);
}
for (const button of incrementButtons) {
	button.addEventListener("click", increaseAmount);
}
for (const button of decrementButtons) {
	button.addEventListener("click", decreaseAmount);
}
for (const button of removeButtons) {
	button.addEventListener("click", removeFromCart);
}

async function showProductPopup(event) {
	//dont show popup if user was interacting with a button
	if (event.target.tagName === "BUTTON") {return}
	const productID = event.target.closest(".product-row").dataset.productId;
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

async function removeFromCart(event) {
	const removeButton = event.target;
	const productRow = removeButton.closest(".product-row");
	const productID = productRow.dataset.productId;

	const response = await fetch("/cart/remove", {
		method: "POST",
		headers: {
			"Content-Type": "application/json",
		},
		body: JSON.stringify({ productID })
	});

	const data = await readJsonSafely(response);

	if (response.ok) {
		showAppFeedback(data.message || "Item removed from cart.", "success");
		window.location.reload();
	} else {
		showAppFeedback(data.message || "Could not remove the item.", "error");
	}
}

let incrementTimer = null;
let incrementStartValue = null;
//increase the quantity display for the amount of items of a product
function increaseAmount(event) {
	clearTimeout(incrementTimer);
	const controlDiv = event.target.parentElement;
	const productRow = controlDiv.parentElement.parentElement;
	const productID = productRow.dataset.productId;
	const amountDisplay = controlDiv.querySelector(".amount-value");
	const priceEl = productRow.querySelector(".product-price")
	let currentAmount = amountDisplay.innerText++;

	if(incrementStartValue==null){
		incrementStartValue = currentAmount;
	}

	incrementTimer = setTimeout(async()=> {
		const response = await fetch("/cart/update", {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
			},
			body: JSON.stringify({
				productID: productID,
				amount: Number(currentAmount)+1
			})
		});

		if (!response.ok) {
			amountDisplay.innerText = incrementStartValue;
			const errorData = await readJsonSafely(response);
			showAppFeedback(errorData.message || "Could not update quantity.", "error");
		}
		else {
			const responseData = await response.json();
			newPointAmount = responseData.newPriceDisplay;
			priceEl.innerText = `${newPointAmount} Points`;
		}
		incrementStartValue=null;
	}, 500);
}


let decrementTimer = null;
let decrementStartValue = null;
//decrease the quantity display for the amount of items of a product
function decreaseAmount(event) {
	clearTimeout(decrementTimer);
	const controlDiv = event.target.parentElement;
	const productRow = controlDiv.parentElement.parentElement;
	const priceEl = productRow.querySelector(".product-price");
	const productID = productRow.dataset.productId;
	const amountDisplay = controlDiv.querySelector(".amount-value");
	let currentAmount = amountDisplay.innerText;

	if (currentAmount > 1) {
		--amountDisplay.innerText;
	}
	else {
		++currentAmount;
	}

	if(decrementStartValue==null){
		decrementStartValue = currentAmount;
	}

	decrementTimer = setTimeout(async()=> {
		const response = await fetch("/cart/update", {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
			},
			body: JSON.stringify({
				productID: productID,
				amount: Number(currentAmount)-1
			})
		});

		if (!response.ok) {
			amountDisplay.innerText = decrementStartValue;
			const errorData = await readJsonSafely(response);
			showAppFeedback(errorData.message || "Could not update quantity.", "error");
		}
		else {
			responseData = await response.json();
			const newPointAmount = responseData.newPriceDisplay;
			priceEl.innerText = `${newPointAmount} Points`;
		}
		decrementStartValue = null;
	}, 500);
}