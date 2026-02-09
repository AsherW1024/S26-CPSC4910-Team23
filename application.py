from flask import Flask, render_template, redirect, url_for, request, session, flash
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
import pymysql
from config import db_config
import os

application = Flask(__name__)
application.secret_key = os.urandom(24)  # Use a secure random key in production

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
	#query db to find out how many accounts are in accounts table
	accountCount = queryDb("SELECT count(*), count(account_id) FROM accounts")
	accountCount = accountCount['count(*)']

	if 'UserID' in session:
		return render_template("about.html", layout = "activenav.html",  accountCount=accountCount)
	return render_template("about.html", layout = "nav.html",  accountCount=accountCount)

@application.route("/login")
def login():
	return render_template("login.html")

@application.route("/login", methods=["POST"])
def loginUser():

	identifier = request.form.get("identifier")
	exists = paramQueryDb("SELECT UserID, Password_hash FROM Users WHERE Email = %s or Username = %s", (identifier, identifier))

	if not exists:
		flash("Please enter the correct credentials", "username")
		return redirect(url_for("login"))

	password = request.form.get("password")
	hashPassword = exists["Password_hash"]

	if not exists or not check_password_hash(hashPassword, password):
		flash("Please enter the correct credentials", "password")
		return redirect(url_for("login"))

	session['UserID'] = exists['UserID']
	return redirect(url_for("home"))

@application.route("/register")
def register():
	return render_template("register.html")

@application.route("/register", methods=["POST"])
def registerUser():
	sponsor = False
	if 'createOrg' in session:
		sponsor = True
		organization = session['createOrg']
		session.pop("createOrg", None)

	email = request.form.get("email")

	exists = paramQueryDb("SELECT UserID FROM Users WHERE Email=%s", (email,))

	if exists:
		flash("User already has an account", "registered")
		return redirect(url_for("login"))

	name = request.form.get("name")
	username = request.form.get("username")
	password = request.form.get("password")
	if not username or not password:
		return redirect(url_for("register"))
	hashPassword = generate_password_hash(password)
	timeCreated = datetime.now()

	print("RAW USERNAME:", repr(username))

	if "admin" in username.strip().lower():
		insertDb(
			"""INSERT INTO Admins (Email, Username, Password_hash, TimeCreated)
			VALUES (%s, %s, %s, %s)""", (email, username, hashPassword, timeCreated))
		flash("Admin account created please login", "created")
	else:
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

@application.route("/catalog")
def catalog():
	return render_template("catalog.html")

@application.route("/profile")
def profile():
	profile = paramQueryDb("SELECT * FROM Users WHERE UserID = %s", (session["UserID"],))
	return render_template("profile.html", layout = "activenav.html", name=profile["Name"], username=profile["Username"], email=profile["Email"])

@application.route("/logout")
def logout():
	session.pop("UserID", None)
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