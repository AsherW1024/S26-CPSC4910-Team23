//add event listeners
document.querySelectorAll('.product-update').forEach(box => box.addEventListener("input", search));
document.getElementById("filter-button").addEventListener("click", toggleMenu);
document.getElementById("category").addEventListener("input", search)

//store all product data for the page for when we expand to show more detail
let pageProductData;

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
		productImg.src = product.images[0];
		//product name show in the catalog grid
		let name = document.createElement("h3");
		name.innerText = product.title;
		//product price shown in the catalog grid
		let price = document.createElement("p");
		price.innerText = "$"+product.price;

		//establish relationships between elements
		productDiv.appendChild(productImg);
		productDiv.appendChild(name);
		productDiv.appendChild(price);
		
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

//one time pull for products when user loads the page for the first time
queryProducts();