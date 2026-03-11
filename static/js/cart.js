incrementButtons = document.querySelectorAll(".increment-button");
decrementButtons = document.querySelectorAll(".decrement-button");
removeButtons = document.querySelectorAll(".remove-cart-item");

for (const button of incrementButtons) {
	button.addEventListener("click", increaseAmount);
}
for (const button of decrementButtons) {
	button.addEventListener("click", decreaseAmount);
}
for (const button of removeButtons) {
	button.addEventListener("click", removeFromCart);
}

async function removeFromCart(event) {
	const removeButton = event.target;
	const productRow = removeButton.parentElement.parentElement.parentElement;
	const productID = productRow.dataset.productId;
	
	response = await fetch("/cart/remove", {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
		},
		body: JSON.stringify({
			productID: productID
		})
	});
	window.location.reload();
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
	let currentAmount = amountDisplay.innerText++;

	if(incrementStartValue==null){
		incrementStartValue = currentAmount;
	}

	incrementTimer = setTimeout(async()=> {
		response = await fetch("/cart/update", {
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
	const productID = productRow.dataset.productId;
	const amountDisplay = controlDiv.querySelector(".amount-value");
	let currentAmount = amountDisplay.innerText;
	if (currentAmount > 1) {
		--amountDisplay.innerText;
	}
	else {
		return
	}

	if(decrementStartValue==null){
		decrementStartValue = currentAmount;
	}

	decrementTimer = setTimeout(async()=> {
		response = await fetch("/cart/update", {
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
			amountDisplay.innerText = decrementStartValue;
		}
		decrementStartValue=null;
	}, 500);
}