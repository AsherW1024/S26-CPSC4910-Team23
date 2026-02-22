//add event listeners
document.querySelectorAll('.product-update').forEach(box => box.addEventListener("input", search));
document.getElementById("filter-button").addEventListener("click", toggleMenu);
document.getElementById("category").addEventListener("input", search)

//store all product data for the page for when we expand to show more detail
let pageProductData;

//find the value for each point
let pointValue;
fetch("/point_value")
.then(response => response.json())
.then(data => {
	pointValue = data.pointValue;
})
.catch(error => {
	console.log("Error:", error);
});

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

	let response = await fetch ("/get_products", {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
		},
		body: JSON.stringify({
			query: query,
			minPrice: minPrice,
			maxPrice: maxPrice,
			category: category
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
		productDiv.dataset.index = index;
		//image shown in catalog grid
		let productImg = document.createElement("img")
		productImg.src = product.thumbnail;
		//product name show in the catalog grid
		let name = document.createElement("h3");
		name.innerText = product.title;
		//product price shown in the catalog grid
		let price = document.createElement("p");
		price.innerText = product.price+ " Points";

		//establish relationships between elements
		productDiv.appendChild(productImg);
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

function showProductDetails() {
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