let BASE_URL = "https://dummyjson.com/products/search?";
let SEARCH_QUERY = "";
let LIMIT_PARAM = "limit=300"

//add event listeners
document.getElementById("search-box").addEventListener("input", debounceSearch);

//function used to delay search execution to not send a million api request
//as user types out their search
let searchTimer;
function debounceSearch(time) {
	clearTimeout(searchTimer);
	searchTimer = setTimeout(()=>updateQuery(), 400);
}

//update page with products relating to search
function updateQuery() {
	let searchBox = document.getElementById("search-box");

	//if the user has no input, don't provide query parameters to api
	if (searchBox.value.trim()==="") {
		SEARCH_QUERY = "";
	}
	else {
		SEARCH_QUERY = "q="+searchBox.value;
	}
	getProducts();
}

//get request from api
async function queryAPI() {
	let fullUrl = BASE_URL+LIMIT_PARAM+"&"+SEARCH_QUERY;
	const response = await fetch(fullUrl);
	if (!response.ok) {
		throw new Error(response.status);
	}
	return response.json();
}

//add product info to page
async function getProducts() {
	try {
		const response = await queryAPI();

		let products;
		products = response.products

		//make sure the grid is clear
		let grid = document.getElementsByClassName("grid")[0];
		grid.innerHTML = "";

		//move each product into the html
		products.forEach(product => {
			//product container
			let productDiv = document.createElement("div");
			productDiv.classList.add("product");
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
	catch (err) {
		console.error(err);
	}
}

getProducts();