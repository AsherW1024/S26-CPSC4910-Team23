incrementButtons = document.querySelectorAll(".increment-button");
decrementButtons = document.querySelectorAll(".decrement-button");

for (const button of incrementButtons) {
	button.addEventListener("click", increaseAmount);
}
for (const button of decrementButtons) {
	button.addEventListener("click", decreaseAmount);
}

//increase the quantity display for the amount of items of a product
function increaseAmount(event) {
	console.log("increasing");
}

//decrease the quantity display for the amount of items of a product
function decreaseAmount(event) {
	console.log("decreasing");
}