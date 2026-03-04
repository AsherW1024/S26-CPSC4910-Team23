//add event listeners
document.querySelectorAll('.product-update').forEach(box => box.addEventListener("input", search));
document.getElementById("filter-button").addEventListener("click", toggleMenu);
document.getElementById("category").addEventListener("input", search)
document.getElementById("sort-type").addEventListener("input", search)
document.getElementById("sort-direction").addEventListener("input", search)
let allRemoveButtons = document.querySelectorAll(".remove-button");
allRemoveButtons.forEach(removeButton => {
	removeButton.addEventListener("click", removeProduct)
});

//store all product data for the page for when we expand to show more detail
let pageProductData;

//find user's role
async function getUserRole() {
	let response = await fetch("/user/role");
	let data = await response.json();
	let userRole = data.role;

	if (response.status == 200){
		return userRole;
	}
	else {
		return "";
	}
}

//remove product from catalog
async function removeProduct(event) {
	let removeButton = event.target;
	let productDiv = removeButton.parentElement;

	let productIndex = productDiv.dataset.index;
	
	let productID = pageProductData[productIndex].id;
	
	let response = await fetch("exclude_product", {method: 'POST',
		headers: {
			'Content-Type': 'application/json',
		},
		body: JSON.stringify({
			productID: productID,
			action: "remove"
		})
	});
	let data = await response.json();
	
	if (response.status == 200) {
		productDiv.classList.add("not-included");
		removeButton.classList.remove("remove-button");
		removeButton.classList.add("add-button");
		removeButton.innerText="Add";
		removeButton.removeEventListener("click", removeProduct);
		removeButton.addEventListener("click", addProduct);
	}
}

//returns list of product ids that are not shown to drivers
async function getExcludedProducts() {
	let response = await fetch("/exclude_product");
	let data = await response.json();
	let excludedProducts = data.products;

	if (response.status == 200){
		return excludedProducts;
	}
	else {
		return [];
	}
}

async function addProduct(event) {
	let addButton = event.target;
	let productDiv = addButton.parentElement;

	let productIndex = productDiv.dataset.index;
	
	let productID = pageProductData[productIndex].id;
	
	let response = await fetch("exclude_product", {method: 'POST',
		headers: {
			'Content-Type': 'application/json',
		},
		body: JSON.stringify({
			productID: productID,
			action: "add"
		})
	});
	let data = await response.json();
	
	if (response.status == 200) {
		productDiv.classList.remove("not-included");
		addButton.classList.remove("add-button");
		addButton.classList.add("remove-button");
		addButton.innerText="Remove";
		addButton.removeEventListener("click", addProduct);
		addButton.addEventListener("click", removeProduct);
	}
}

async function addToWishlist(event) {
	let wishlistButton = event.target;
	let productDiv = wishlistButton.parentElement;

	let productDetailIndex = productDiv.dataset.index;

	let productID = pageProductData[productDetailIndex].id;

	let request = await fetch("/wishlist/add", {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
		},
		body: JSON.stringify({
			productID: productID
		})
	});
	let response = await request.json();
	if (request.ok) {
		wishlistButton.classList.remove("wishlist-button-inactive");
		wishlistButton.classList.add("wishlist-button-active");
		wishlistButton.removeEventListener("click", addToWishlist);
		wishlistButton.addEventListener("click", removeFromWishlist);
	}
}

async function removeFromWishlist(event) {
	let wishlistButton = event.target;
	let productDiv = wishlistButton.parentElement;

	let productDetailIndex = productDiv.dataset.index;

	let productID = pageProductData[productDetailIndex].id;

	let request = await fetch("/wishlist/remove", {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
		},
		body: JSON.stringify({
			productID: productID
		})
	});
	let response = await request.json();
	if (request.ok) {
		wishlistButton.classList.add("wishlist-button-inactive");
		wishlistButton.classList.remove("wishlist-button-active");
		wishlistButton.removeEventListener("click", removeFromWishlist);
		wishlistButton.addEventListener("click", addToWishlist);
	}
}

//make api request in the backend for products
//update screen with results
async function queryProducts() {
	let searchBox = document.getElementById("search-box");
	let query = searchBox.value;
	let minPriceBox = document.getElementById("min-price");
	let minPrice = minPriceBox.value;
	let maxPriceBox = document.getElementById("max-price");
	let maxPrice = maxPriceBox.value;
	let categoryBox = document.getElementById("category");
	let category = categoryBox.value;
	let sortByBox = document.getElementById("sort-type");
	let sortBy = sortByBox.value;
	let sortDirectionBox = document.getElementById("sort-direction");
	let sortDirection = sortDirectionBox.value;
	let userRole = await getUserRole();
	let excludedProducts = []
	if (userRole != "Driver") {
		excludedProducts = await getExcludedProducts();
	}

	let response = await fetch ("/get_products", {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
		},
		body: JSON.stringify({
			query: query,
			minPrice: minPrice,
			maxPrice: maxPrice,
			category: category,
			sortBy: sortBy,
			sortDirection: sortDirection
		})
	});
	let data = await response.json();
	let products = data.products;
	pageProductData = products;

	//clear grid / products
	let grid = document.getElementsByClassName("grid")[0];
	grid.innerHTML = "";

	//move each product into the html
	products.forEach((product, index) => {
		//product container
		let productDiv = document.createElement("div");
		productDiv.classList.add("product");
		if (excludedProducts.includes(product.id)) {
			productDiv.classList.add("not-included");
		}
		productDiv.dataset.index = index;
		//image shown in catalog grid
		let productImg = document.createElement("img")
		productImg.src = product.thumbnail;
		//product name show in the catalog grid
		let name = document.createElement("h3");
		name.innerText = product.title;
		//product price shown in the catalog grid
		let price = document.createElement("p");
		price.innerText = product.price+" Points";

		//establish relationships between elements
		productDiv.appendChild(productImg);
		//add a remove product button for Sponsors
		if (userRole == "Sponsor" && !(excludedProducts.includes(product.id))) {
			let removeButton = document.createElement("button");
			removeButton.classList.add("remove-button");
			removeButton.innerText = "Remove";
			removeButton.addEventListener("click", removeProduct);
			productDiv.appendChild(removeButton);
		}
		else if (userRole == "Sponsor" && excludedProducts.includes(product.id)) {
			let addButton = document.createElement("button");
			addButton.classList.add("add-button");
			addButton.innerText = "Add";
			addButton.addEventListener("click", addProduct);
			productDiv.appendChild(addButton);
		}
		else if (userRole == "Driver") {
			let wishlistButton = document.createElement("button");
			wishlistButton.innerText = "★";
			productDiv.appendChild(wishlistButton);
			if (product.wishlisted) {
				wishlistButton.classList.add("wishlist-button-active");
				wishlistButton.addEventListener("click", removeFromWishlist)
			}
			else {
				wishlistButton.classList.add("wishlist-button-inactive");
				wishlistButton.addEventListener("click", addToWishlist)
			}
		}
		productDiv.appendChild(name);
		productDiv.appendChild(price);

		//give product div an event listener that opens up the advanced details
		productDiv.addEventListener("click", showProductDetails)

		//append elements to the grid;
		grid.appendChild(productDiv);
	});
}

//function used to delay search execution to not send a million api request
//as user types out their search
let searchTimer;
function search() {
	clearTimeout(searchTimer);
	searchTimer = setTimeout(()=>queryProducts(), 400);
}

function toggleMenu() {
	let filterMenu = document.getElementById("filter-menu");
	let filterButton = document.getElementById("filter-button");
	if (filterMenu.classList.contains("closed")) {
		filterMenu.classList.toggle("closed")
		filterButton.innerText = "Sorting & Filters ▲";
	}
	else {
		filterMenu.classList.toggle("closed");
		filterButton.innerText = "Sorting & Filters ▼";
	}
}

function closePopup() {
	let popupEl = document.getElementById("popup-overlay-bg");
	popupEl.innerHTML = "";
	popupEl.hidden = true;
}

function showProductDetails(event) {
	//no action if the remove or add button was pressed
	if (event.target.classList.contains("remove-button")) {return}
	if (event.target.classList.contains("add-button")) {return}
	if (event.target.classList.contains("wishlist-button-inactive")) {return}
	if (event.target.classList.contains("wishlist-button-active")) {return}

	let productDetailIndex = this.dataset.index;
	let productDetails = pageProductData[productDetailIndex];
	console.log(productDetails)

	let productDetailsHtml = `
		<div id="popup-content-bg">
			<div id="popup-content-div">
				<button id="popup-close">X</button>
				<div id="popup-images"></div>
				<h2>${productDetails.title}</H3>
				<div id="popup-price">
					<div class="side-by-side">
						<h3>Point Cost:</h3>
						<p>${productDetails.price} Points</p>
					</div>
				</div>
				<div id="popup-availability">
					<div class="side-by-side">
						<h3>Availability:</h3>
						<p>${productDetails.availabilityStatus}</p>
					</div>
					<div class="side-by-side">
						<h3>Stock:</h3>
						<p>${productDetails.stock}</p>
					</div>
				</div>
				<div id="popup-brand">
					<div class="side-by-side">
						<h3>Brand:</h3>
						<p>${productDetails.brand}</p>
					</div>
				</div>
				<div id="popup-description">
					<div class="side-by-side">
						<h3>Description:</h3>
						<p>${productDetails.description}</p>
					</div>
				</div>
				<div id="popup-dimensions">
					<h3>Dimensions:</h3>
					<div class="side-by-side">
						<h4>Depth:</h4>
						<p>${productDetails.dimensions["depth"]} in</p>
					</div>
					<div class="side-by-side">
						<h4>height:</h4>
						<p>${productDetails.dimensions["height"]} in</p>
					</div>
					<div class="side-by-side">
						<h4>width:</h4>
						<p>${productDetails.dimensions["width"]} in</p>
					</div>
				</div>
				<div id="popup-rating">
					<h3>Overall Rating</h3>
					<p>${productDetails.rating}/5</p>
				</div>
				<div id="popup-reviews">
					<h3>Reviews</h3>
				</div>
			</div>
		</div>
	`;

	//add product popup html to page
	let popupEl = document.getElementById("popup-overlay-bg");
	popupEl.innerHTML = productDetailsHtml;

	//add each image
	let imageDiv = document.getElementById("popup-images");
	productDetails.images.forEach(image => {
		let imageEl = document.createElement("img");
		imageEl.src = image;
		imageDiv.appendChild(imageEl);
	})

	//add each review
	productDetails.reviews.forEach(review => {
		let reviewDiv = document.createElement("div");
		reviewDiv.classList.add("review-div");
		let reviewName = document.createElement("h4");
		reviewName.innerText = review.reviewerName;
		let reviewScore = document.createElement("p");
		reviewScore.innerText = `${review.rating}/5`;
		let reviewComment = document.createElement("p");
		reviewComment.innerText = review.comment;

		//establish relationships between elements
		reviewDiv.appendChild(reviewName);
		reviewDiv.appendChild(reviewScore);
		reviewDiv.appendChild(reviewComment);
		
		//add to reviews div
		document.getElementById("popup-reviews").appendChild(reviewDiv);
	});

	//add close button listener
	document.getElementById("popup-close").addEventListener("click", closePopup);

	//show product page popup
	popupEl.hidden = false;
}

//one time pull for products when user loads the page for the first time
queryProducts();