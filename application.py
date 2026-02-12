from flask import Flask, render_template, redirect, url_for, request, session, flash, jsonify
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
import pymysql
from config import db_config
import os
import requests

application = Flask(__name__)
application.secret_key = os.urandom(24)  # Use a secure random key in production
application.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=1)

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
			results = cursor.fetchall()
		return results[0]
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

#Creating accounts and organizations
@application.route("/register")
def register():
	return render_template("register.html")

@application.route("/sponsorRegister")
def sRegister():
	return render_template("sponsorRegister.html")

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

	confirm_password = request.form.get("confirm_password")

	exists = paramQueryDb("SELECT UserID FROM Users WHERE Email=%s OR Username=%s", 
		(email, username))

	if exists:
		flash("User already has an account", "registered")
		return redirect(url_for("login"))

	name = request.form.get("name")
	username = request.form.get("username")
	password = request.form.get("password")
	if not username or not password or not confirm_password:
		flash("Missing required fields.", "missing")
		if sponsor:
			return redirect(url_for("sRegister"))
		else:	
			return redirect(url_for("register"))
	
	if password != confirm_password:
		flash("Passwords do not match.", "mismatch")
		if sponsor:
			return redirect(url_for("sRegister"))
		else:	
			return redirect(url_for("register"))

	hashPassword = generate_password_hash(password)
	timeCreated = datetime.now()
	adminCount = queryDb("SELECT COUNT(*) as count FROM Users WHERE UserType = 'a'")
	if "admin" in username.strip().lower() and adminCount['count'] == 0:
		insertDb(
			"""INSERT INTO Users (Email, Username, Password_hash, TimeCreated, UserType)
			VALUES (%s, %s, %s, %s, %s)""", (email, username, hashPassword, timeCreated, "a"))
		newUser = paramQueryDb("SELECT UserID FROM Users WHERE Email=%s OR Username=%s", 
			(email, username))
		insertDb(
			"""INSERT INTO Admins (AdminID, Name)
			VALUES (%s, %s)""", (newUser['UserID'], name))
		flash("Admin account created please login", "created")
	else:
		if not sponsor and not organization:
			organization = request.form.get("organizationName")	
		if sponsor:
			insertDb(
				"""INSERT INTO Users (Email, Username, Password_hash, TimeCreated, UserType)
				VALUES (%s, %s, %s, %s, %s)""", (email, username, hashPassword, timeCreated, "s"))
			newUser = paramQueryDb("SELECT UserID FROM Users WHERE Email=%s OR Username=%s", 
				(email, username))
			insertDb(
				"""INSERT INTO Sponsors (SponsorID, Name, OrganizationName)
				VALUES (%s, %s, %s)""", (newUser['UserID'], name, organization))
			flash("Sponsor account created please login", "created")
		else:	
			insertDb(
				"""INSERT INTO Users (Email, Username, Password_hash, TimeCreated, UserType)
				VALUES (%s, %s, %s, %s, %s)""", (email, username, hashPassword, timeCreated, "d"))
			newUser = paramQueryDb("SELECT UserID FROM Users WHERE Email=%s OR Username=%s", 
				(email, username))
			insertDb(
				"""INSERT INTO Drivers (DriverID, Name, OrganizationName)
				VALUES (%s, %s, %s)""", (newUser['UserID'], name, organization))
			flash("User account created please login", "created")

	return redirect(url_for("login"))

@application.route("/createOrg")
def createOrganization():
	return render_template("createOrg.html")
	
@application.route("/createOrg", methods = ["POST"])
def registerOrganization():
	orgName = request.form.get("organizationName")
	timeCreated = datetime.now()

	exists = paramQueryDb("SELECT OrganizationID FROM Organizations WHERE Name=%s", 
		(orgName,))

	if exists:
		flash("Organization already exists", "registeredOrg")
		return redirect(url_for("login"))

	insertDb(
			"""INSERT INTO Organizations (Name, TimeCreated)
			VALUES (%s, %s)""", (orgName, timeCreated))

	session["createOrg"] = orgName
	return redirect(url_for("sRegister"))


#Logging in and out 
@application.route("/login")
def login():
	session.setdefault('attempts', 5)
	if 'lockoutTime' in session:
		lockout = datetime.fromisoformat(session.get('lockoutTime'))
		now = datetime.utcnow()
		if now < lockout:
			session['attempts'] = 5
			remainingTime = lockout - now
			minutesRemaining = int(remainingTime.total_seconds() // 60) + 1
			flash("Too many failed attempts. Locked for %d minutes." % minutesRemaining, "failedAttempts")
			return render_template("login.html")
		else:
			session.pop('lockoutTime', None)
	return render_template("login.html")

@application.route("/login", methods=["POST"])
def loginUser():

	if session['attempts'] <= 0:
		session['lockoutTime'] = (datetime.utcnow() + timedelta(minutes=15)).isoformat()

	if 'lockoutTime' in session:
		lockout = datetime.fromisoformat(session.get('lockoutTime'))
		now = datetime.utcnow()
		if now < lockout:
			session['attempts'] = 5
			return redirect(url_for("login"))
		else:
			session.pop('lockoutTime', None)

	identifier = request.form.get("identifier")
	exists = paramQueryDb("SELECT UserID AS id, Password_hash, UserType FROM Users WHERE Email=%s OR Username=%s", 
		(identifier, identifier))

	if not exists:
		session['attempts'] -= 1
		flash("Please enter the correct credentials, Attempts left %d of 5" % (session['attempts'] + 1), "username")
		return redirect(url_for("login"))

	password = request.form.get("password")
	hashPassword = exists["Password_hash"]

	if not exists or not check_password_hash(hashPassword, password):
		session['attempts'] -= 1
		flash("Please enter the correct credentials, Attempts left %d of 5" % (session['attempts'] + 1), "password")
		return redirect(url_for("login"))

	remember = request.form.get("remember")
	if remember:
		session.permanent = True
	else:
		session.permanent = False

	session.pop('attempts', None)
	session['UserID'] = exists['id']
	session['role'] = exists['UserType']

	return redirect(url_for("home"))

@application.route("/logout")
def logout():
	session.pop("UserID", None)
	return redirect(url_for("home"))


#The different website pages
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
	#query db to find out how many accounts are in accounts table
	aboutInfo = queryDb("SELECT TeamNum, VersionNum, ReleaseDate, ProductName, ProductDescription FROM Admins WHERE AdminID = 1")

	if 'UserID' in session:
		if session['role'] == "a":
			return render_template("adminAbout.html", layout = "activenav.html", Team=aboutInfo['TeamNum'], Version=aboutInfo['VersionNum'], 
			Release=aboutInfo['ReleaseDate'], Name=aboutInfo['ProductName'], Description=aboutInfo['ProductDescription'])
		return render_template("about.html", layout = "activenav.html", Team=aboutInfo['TeamNum'], Version=aboutInfo['VersionNum'], 
			Release=aboutInfo['ReleaseDate'], Name=aboutInfo['ProductName'], Description=aboutInfo['ProductDescription'])
	return render_template("about.html", layout = "nav.html", Team=aboutInfo['TeamNum'], Version=aboutInfo['VersionNum'], 
		Release=aboutInfo['ReleaseDate'], Name=aboutInfo['ProductName'], Description=aboutInfo['ProductDescription'])

@application.route("/about/edit")
def editAbout():
	return render_template("editAbout.html", layout="activenav.html")

@application.route("/about/edit", methods=["POST"])
def registerAboutEdits():
	team = request.form.get("team")
	version = request.form.get("version")
	release = request.form.get("release")
	name = request.form.get("name")
	description = request.form.get("description")

	update = []
	identifier = []

	if team:
		identifier.append("TeamNum= %s")
		update.append(team)
	if version:
		identifier.append("VersionNum = %s")
		update.append(version)
	if release:
		identifier.append("ReleaseDate = %s")
		update.append(release)
	if name:
		identifier.append("ProductName = %s")
		update.append(name)
	if description:
		identifier.append("ProductDescription = %s")
		update.append(description)

	insertDb(
		f"""UPDATE Admins SET {",".join(identifier)} WHERE AdminID = 1""", update)

	return redirect(url_for("about"))


@application.route("/profile")
def profile():

	if "UserID" not in session:
		return redirect(url_for("login"))

	accountType = paramQueryDb("SELECT UserType FROM Users WHERE UserID = %s", 
		(session["UserID"],))
	if session["role"] == "a":
		profile = paramQueryDb("SELECT Name, Email, Username FROM Users u JOIN Admins a ON u.UserID = a.AdminID WHERE u.UserID = %s", 
			(session["UserID"],))
	elif session["role"] == "s":
		profile = paramQueryDb("SELECT Name, Email, Username FROM Users u JOIN Sponsors s ON u.UserID = s.SponsorID WHERE u.UserID = %s", 
			(session["UserID"],))
	elif session["role"] == "d":
		profile = paramQueryDb("SELECT Name, Email, Username FROM Users u JOIN Drivers d ON u.UserID = d.DriverID WHERE u.UserID = %s", 
			(session["UserID"],))
	
	return render_template("profile.html", layout = "activenav.html", 
		name=profile["Name"], username=profile["Username"], email=profile["Email"])

@application.route("/settings")
def settings():
	return render_template("settings.html", layout = "activenav.html") 


#Catalog and filtering
@application.route("/catalog")
def catalog():
	if 'UserID' in session:
		return render_template("catalog.html", layout="activenav.html")
	return render_template("catalog.html", layout="nav.html")

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
	result = filterByPrice(data=result, min=minPrice, max=maxPrice)

	return jsonify(result)

"""
This lets us test locally. Should not execute in AWS
"""
if __name__ == "__main__":
	application.run()