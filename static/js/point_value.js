//element references
let submitButton = document.getElementById("point-value-submit");
let dropdownButton = document.getElementById("change-points-dropdown");
let controlMenu = document.getElementById("point-value-control");

//dropdown button state
let controlsHidden = true;

//send point request value to backend, validate, get back response
function pointValueRequest() {
	let inputBox = document.getElementById("point-value-input");
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
	.then(response => response.text())
	.then(data => console.log(data));
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

//submit button event listener setup
submitButton.addEventListener("click", pointValueRequest);

//dropdown buttone event listener setup
dropdownButton.addEventListener("click", toggleMenu);