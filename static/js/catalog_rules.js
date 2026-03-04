//element references
keepAllCategoriesCB = document.getElementById("keep-all-categories");
keepAllBrandsCB = document.getElementById("keep-all-brands");
categorySelectionDiv = document.getElementById("allowed-categories");
brandSelectionDiv = document.getElementById("allowed-brands");
categoryCBs = document.getElementsByName("category");
brandCBs = document.getElementsByName("brand");

function toggleCategoriesVisibility(event) {
	isChecked = event.target.checked;

	//hide category selection menu and check all the cbs
	if (isChecked) {
		categorySelectionDiv.hidden = true;
		categoryCBs.forEach(checkbox => {
			checkbox.checked = true;
		});
	}
	//show category selection menu and uncheck all the cbs
	else {
		categorySelectionDiv.hidden = false;
		categoryCBs.forEach(checkbox => {
			checkbox.checked = false;
		});
	}
}

function toggleBrandsVisibility(event) {
	isChecked = event.target.checked;

	//hide category selection menu and check all the cbs
	if (isChecked) {
		brandSelectionDiv.hidden = true;
		brandCBs.forEach(checkbox => {
			checkbox.checked = true;
		});
	}
	//show category selection menu and uncheck all the cbs
	else {
		brandSelectionDiv.hidden = false;
		brandCBs.forEach(checkbox => {
			checkbox.checked = false;
		});
	}
}



// EVENT LiSTENERS

//hide category and brand selection if user is keeping all
keepAllCategoriesCB.addEventListener("input", toggleCategoriesVisibility)
keepAllBrandsCB.addEventListener("input", toggleBrandsVisibility)