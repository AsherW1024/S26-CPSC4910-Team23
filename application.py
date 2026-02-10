from flask import Flask, render_template, redirect, url_for, request, session, flash, jsonify
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
import pymysql
from config import db_config
import os
import requests
from functools import wraps
from flask import abort

application = Flask(__name__)
application.secret_key = os.environ.get("SECRET_KEY", "dev-only-change-me")  # Replace with your own secret key for production (so that admins do not randomly lose access to their accounts)

"""
This is a decorator function that checks if the user is an admin before allowing access to certain routes. 
If the user is not an admin, it will return a 403 error. 
To use this decorator, simply add @admin_required above the route function that you want to protect. 
For example: @application.route("/admin", methods=["GET", "POST"]
"""
def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if session.get("role") != "admin":
            abort(403)
        return fn(*args, **kwargs)
    return wrapper

"""
This is the route for the about page editing access. It queries the database for the most recent about content and displays it on the page. 
If the user is an admin, they will see an edit button that allows them to edit the about content.
"""
@application.route("/about/edit")
@admin_required
def edit_about():
	about = paramQueryDb("SELECT body FROM AboutContent ORDER BY id DESC LIMIT 1")
	body = about["body"] if about else ""
	return render_template("about_edit.html", body=body, layout="activenav.html")

"""
This is the route that handles the form submission for editing the about content. 
It inserts the new content into the database and redirects back to the about page. 
Only admins can access this route. 
"""
@application.route("/about/edit", methods=["POST"])
@admin_required
def save_about():
    body = request.form.get("body", "").strip()

    admin_id = session.get("UserID")
    if not admin_id:
        abort(403)

    insertDb(
        "INSERT INTO AboutContent (body, updated_at, updated_by_admin_id) VALUES (%s, %s, %s)",
        (body, datetime.now(), admin_id)
    )

    flash("About page updated.", "success")
    return redirect(url_for("about"))

"""
This uses the data provided in the db_config.py file to intinialize and return
a reference to the db connection. db_config.py is located in the config directory.
The config directory should never be uploaded to github.
"""
def getDbConnection():
	return pymysql.connect(
		host=db_config.DB_HOST,
		user=db_config.DB_USER,
		password=db_config.DB_PASSWORD,
		database=db_config.DB_NAME,
		cursorclass=pymysql.cursors.DictCursor
	)

"""
This function is simplifiy the process of making db quries. Just provide the query
as a string, and the function will return the result as a dictionary.
"""
def queryDb(query: str):
	connection = getDbConnection()
	try:
		with connection.cursor() as cursor:
			cursor.execute(query)
			return cursor.fetchone()  # returns None if no rows match the query
	except Exception as e:
		print(e)
	finally:
		connection.close()
	
def paramQueryDb(query: str, params=None):
	connection = getDbConnection()
	try:
		with connection.cursor() as cursor:
			cursor.execute(query, params)
			return cursor.fetchone()
	except Exception as e:
		print(e)
	finally:
		connection.close()

def insertDb(query: str, params=None):
	connection = getDbConnection()
	try:
		with connection.cursor() as cursor:
			cursor.execute(query, params)
			connection.commit()
	except Exception as e:
		print(e)
	finally:
		connection.close()

#@application.route("/")
#def welcome():
#	return render_template("welcome.html")

@application.route("/")
def home():
	if 'UserID' in session:
		return render_template("home.html", layout = "activenav.html")
	return render_template("home.html", layout = "nav.html")

"""
This is the about page. Right now it serves as the landing page. Later this will
need to be changed to have a different route. '@application.route("/about/")'
for example.
"""
@application.route("/about")
def about():
    # safer: alias the count column so you don't depend on 'count(*)'
    accountCountRow = queryDb("SELECT COUNT(*) AS cnt FROM accounts")
    accountCount = accountCountRow["cnt"] if accountCountRow else 0

    about_row = paramQueryDb("SELECT body FROM AboutContent ORDER BY id DESC LIMIT 1")
    body = about_row["body"] if about_row else ""

    is_admin = session.get("role") == "admin"
    layout = "activenav.html" if "UserID" in session else "nav.html"

    return render_template(
        "about.html",
        layout=layout,
        accountCount=accountCount,
        body=body,
        is_admin=is_admin
    )

@application.route("/login")
def login():
	return render_template("login.html")

@application.route("/login", methods=["POST"])
def loginUser():

	identifier = request.form.get("identifier")
	exists = paramQueryDb("SELECT UserID AS id, Password_hash, 'driver' AS role FROM Users WHERE Email=%s OR Username=%s",
                      (identifier, identifier))

	if not exists:
		exists = paramQueryDb("SELECT AdminID AS id, Password_hash, 'admin' AS role FROM Admins WHERE Email=%s OR Username=%s",
                          (identifier, identifier))

	if not exists:
		exists = paramQueryDb("SELECT SponsorID AS id, Password_hash, 'sponsor' AS role FROM Sponsors WHERE Email=%s OR Username=%s",
                          (identifier, identifier))

	if not exists:
		flash("Please enter the correct credentials", "username")
		return redirect(url_for("login"))

	password = request.form.get("password")
	hashPassword = exists["Password_hash"]

	if not exists or not check_password_hash(hashPassword, password):
		flash("Please enter the correct credentials", "password")
		return redirect(url_for("login"))

	session['UserID'] = exists['id']
	session['role'] = exists['role']

	return redirect(url_for("home"))

@application.route("/register")
def register():
	return render_template("register.html")

@application.route("/register", methods=["POST"])
def registerUser():
	sponsor = False
	organization = None
	if 'createOrg' in session:
		sponsor = True
		organization = session['createOrg']
		session.pop("createOrg", None)

	email = request.form.get("email")
	username = request.form.get("username") 

	role = (request.form.get("role") or "driver").strip().lower()
	confirm_password = request.form.get("confirm_password")

	# if role is admin and user is not admin abort with 403 error since only admin can create admin accounts. 
	# This is a security measure to prevent non-admins from creating admin accounts.
	if role == "admin" and session.get("role") != "admin":
		abort(403)

	if role == "sponsor":
		sponsor = True



	exists = paramQueryDb("SELECT UserID FROM Users WHERE Email=%s OR Username=%s", (email, username))
	exists_admin = paramQueryDb("SELECT AdminID FROM Admins WHERE Email=%s OR Username=%s", (email, username))
	exists_sponsor = paramQueryDb("SELECT SponsorID FROM Sponsors WHERE Email=%s OR Username=%s", (email, username))


	if exists or exists_admin or exists_sponsor:
		flash("User already has an account", "registered")
		return redirect(url_for("login"))

	name = request.form.get("name")
	username = request.form.get("username")
	password = request.form.get("password")
	if not username or not password or not confirm_password:
		flash("Missing required fields.", "registered")
		return redirect(url_for("register"))
	
	if password != confirm_password:
		flash("Passwords do not match.", "registered")
		return redirect(url_for("register"))

	hashPassword = generate_password_hash(password)
	timeCreated = datetime.now()

	print("RAW USERNAME:", repr(username))

	if role == "admin":
		insertDb(
			"""INSERT INTO Admins (Email, Username, Password_hash, TimeCreated)
			VALUES (%s, %s, %s, %s)""", (email, username, hashPassword, timeCreated))
		flash("Admin account created please login", "created")
		return redirect(url_for("login"))
	else:
		if sponsor and not organization:
			organization = request.form.get("organizationName")	
		if sponsor and not organization:
			flash("Sponsors must provide an organization name.", "registered")
			return redirect(url_for("register"))
		if sponsor:
			insertDb(
				"""INSERT INTO Sponsors (Email, Username, Password_hash, TimeCreated, OrganizationName)
				VALUES (%s, %s, %s, %s, %s)""", (email, username, hashPassword, timeCreated, organization))
			flash("Sponsor account created please login", "created")
		else:	
			insertDb(
				"""INSERT INTO Users (Email, Name, Username, Password_hash, TimeCreated)
				VALUES (%s, %s, %s, %s, %s)""", (email, name, username, hashPassword, timeCreated))
			flash("User account created please login", "created")

	return redirect(url_for("login"))

"""
helper function used when get_products is called. This removes products that
are not between a min and max price
"""
def filterByPrice(data, min, max):
	#will hold our data filterd based on price
	filteredData = {}
	filteredData["products"] = []

	#first check that the min and max variables are numbers if not empty
	if min!="":
		try:
			float(min)
		except Exception:
			min = ""
	if max!="":
		try:
			float(max)
		except Exception:
			max = ""

	#no min or max value provided
	if min=="" and max=="":
		#no change to data
		return data
	#only a max value provided
	elif min=="" and max!="" and max:
		for product in data["products"]:
			if product["price"] <= float(max):
				filteredData["products"].append(product)
		#only products under the max price		
		return filteredData
	#only a min value provided
	elif min!="" and max =="":
		for product in data["products"]:
			if product["price"] >= float(min):
				filteredData["products"].append(product)
		#only products above the min price		
		return filteredData
	#should only be when both a max and min value are provided
	else:
		for product in data["products"]:
			if product["price"] <= float(max) and product["price"] >= float(min):
				filteredData["products"].append(product)
		#only products between the min and max price		
		return filteredData

@application.route("/get_products", methods=["POST"])
def get_products():
	url = "https://dummyjson.com/products/search?limit=300&q="
	data = request.json
	query = data["query"]
	minPrice = data["minPrice"]
	maxPrice = data["maxPrice"]

	result = requests.get(url+query)
	result = result.json()

	#apply price filters
	result = filterByPrice(data=result, min=minPrice, max=maxPrice);

	return jsonify(result)

@application.route("/catalog")
def catalog():
	return render_template("catalog.html", layout="nav.html")

@application.route("/profile")
def profile():

	if "UserID" not in session:
		return redirect(url_for("login"))
	
	
	role = session.get("role", "driver")

	if role == "admin":
		p = paramQueryDb("SELECT Email, Username FROM Admins WHERE AdminID=%s", (session["UserID"],))
		return render_template("profile.html", layout="activenav.html",
                               name="Admin", username=p["Username"], email=p["Email"])
	
	if role == "sponsor":
		p = paramQueryDb("SELECT Email, Username FROM Sponsors WHERE SponsorID=%s", (session["UserID"],))
		return render_template("profile.html", layout="activenav.html",
                               name="Sponsor", username=p["Username"], email=p["Email"])

	profile = paramQueryDb("SELECT * FROM Users WHERE UserID = %s", (session["UserID"],))
	return render_template("profile.html", layout = "activenav.html", name=profile["Name"], username=profile["Username"], email=profile["Email"])

@application.route("/logout")
def logout():
	session.pop("UserID", None)
	session.pop("role", None)
	return redirect(url_for("home"))

@application.route("/settings")
def settings():
	return render_template("settings.html", layout = "activenav.html") 

@application.route("/createOrg")
def createOrganization():
	return render_template("createOrg.html")
	
@application.route("/createOrg", methods = ["POST"])
def registerOrganization():
	orgName = request.form.get("organizationName")
	timeCreated = datetime.now()

	exists = paramQueryDb("SELECT OrganizationID FROM Organizations WHERE Name=%s", (orgName,))

	if exists:
		flash("Organization already exists", "registeredOrg")
		return redirect(url_for("login"))

	insertDb(
			"""INSERT INTO Organizations (Name, TimeCreated)
			VALUES (%s, %s)""", (orgName, timeCreated))

	session["createOrg"] = orgName
	return redirect(url_for("register"))

"""
This lets us test locally. Should not execute in AWS
"""
if __name__ == "__main__":
	application.run()