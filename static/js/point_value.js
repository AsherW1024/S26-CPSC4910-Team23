//element references
let submitButton = document.getElementById("point-value-submit");
let dropdownButton = document.getElementById("change-points-dropdown");
let controlMenu = document.getElementById("point-value-control");
let errorMessageEl = document.getElementById("error-message");
let pointValueEl = document.getElementById("current-point-value");
let inputBox = document.getElementById("point-value-input");

//dropdown button state
let controlsHidden = true;

//send point request value to backend, validate, get back response
function pointValueRequest() {
	let newPointVal = inputBox.value;

	fetch("/point_value", {
		method: "POST",
		headers: {
			"Content-Type": "application/json"
		},
		body: JSON.stringify({
			newPointVal: newPointVal
		})
	})
	.then(response => response.json())
	.then(data => {
		let error_message = data.message;
		let new_val = data.newPointVal;

		errorMessageEl.innerText = error_message;
		errorMessageEl.hidden = false;
		errorMessageEl.style.color = "darkred";
		if (new_val!="") {
			pointValueEl.innerText = `$${parseFloat(new_val).toFixed(2)}`;
			errorMessageEl.style.color = "green";
		}
	});
}

//hide or unhide point change menu
function toggleMenu() {
	if (controlsHidden) {
		controlMenu.classList.remove("invisible");
		controlsHidden = false;
		dropdownButton.innerText = "Hide Point Menu ▲"
	}
	else {
		controlMenu.classList.add("invisible");
		controlsHidden = true;
		dropdownButton.innerText = "Set A New Value ▼"
	}
}

//hide error message text and clear its contents
function clearErrorMessage() {
	errorMessageEl.innerText = "";
	errorMessageEl.hidden = true;
}

//make point value always display with 2 decimal places
function formatPointVal() {
	let val = inputBox.value;
	val = parseFloat(val).toFixed(2);
	inputBox.value = val;

	let dbPointVal = pointValueEl.innerText.slice(1);
	dbPointVal = parseFloat(dbPointVal).toFixed(2);
	pointValueEl.innerText = `$${dbPointVal}`;
}

//submit button event listener setup
submitButton.addEventListener("click", pointValueRequest);

//dropdown buttone event listener setup
dropdownButton.addEventListener("click", toggleMenu);

//event listeners to clear error messages after input adjustments
inputBox.addEventListener("input", clearErrorMessage);

//event listeners to always show point values as having 2 decimal places
inputBox.addEventListener("change", formatPointVal);
window.addEventListener("load", formatPointVal);