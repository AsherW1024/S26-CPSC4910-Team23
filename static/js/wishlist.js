productDivs = document.querySelectorAll(".product");

//close detailed product view
function closePopup() {
	let popupEl = document.getElementById("popup-overlay-bg");
	popupEl.innerHTML = "";
	popupEl.hidden = true;
}

//popup that displays advanced details about the product
function showProductDetails(event) {
	//no action if the remove or add button was pressed
	if (event.target.classList.contains("remove-button")) {return}
	if (event.target.classList.contains("add-button")) {return}
	if (event.target.classList.contains("wishlist-button-inactive")) {return}
	if (event.target.classList.contains("wishlist-button-active")) {return}

	let productDetailIndex = this.dataset.index;
	let productDetails = pageProductData[productDetailIndex];

	let productDetailsHtml = `
		<div id="popup-content-bg">
			<div id="popup-content-div">
				<button id="popup-close">X</button>
				<div id="popup-images"></div>
				<h2 class="product-name">${productDetails.title}</H3>
				<div id="popup-price">
					<div class="side-by-side">
						<h3 class="popup-label">Point Cost:</h3>
						<p class="popup-data">${productDetails.price} Points</p>
					</div>
				</div>
				<div id="popup-availability">
					<div class="side-by-side">
						<h3 class="popup-label">Availability:</h3>
						<p class="popup-data">${productDetails.availabilityStatus}</p>
					</div>
					<div class="side-by-side">
						<h3 class="popup-label">Stock:</h3>
						<p class="popup-data">${productDetails.stock}</p>
					</div>
				</div>
				<div id="popup-brand">
					<div class="side-by-side">
						<h3 class="popup-label">Brand:</h3>
						<p class="popup-data">${productDetails.brand}</p>
					</div>
				</div>
				<div id="popup-description">
					<div class="side-by-side">
						<h3 class="popup-label">Description:</h3>
						<p class="popup-data">${productDetails.description}</p>
					</div>
				</div>
				<div id="popup-dimensions">
					<h3 class="popup-label">Dimensions:</h3>
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
					<h3 class="popup-label">Overall Rating</h3>
					<p class="popup-data">${productDetails.rating}/5 ★</p>
				</div>
				<div id="popup-reviews">
					<h3 class="popup-label">Reviews</h3>
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
		reviewScore.innerText = `${review.rating}/5 ★`;
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

//give event listener for product details to each product div
for (const productDiv of productDivs) {
	productDiv.addEventListener("click", showProductDetails)
}