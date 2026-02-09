//add event listeners
document.getElementById("search-box").addEventListener("input", search);

//store all product data for the page for when we expand to show more detail
let pageProductData;

//make api request in the backend for products
//update screen with results
async function queryProducts() {
	let searchBox = document.getElementById("search-box");
	let query = searchBox.value;

	let response = await fetch ("/get_products", {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
		},
		body: JSON.stringify({
			query: query
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

//one time pull for products when user loads the page for the first time
queryProducts();