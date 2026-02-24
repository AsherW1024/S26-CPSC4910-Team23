from flask import Flask, render_template, redirect, url_for, request, session, flash, jsonify
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
import pymysql
from config import db_config
import os
import requests
import math

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
	connection = None
	try:
		connection = getDbConnection()
		with connection.cursor() as cursor:
			cursor.execute(query)
			results = cursor.fetchall()
		return results if results else None
	except Exception as e:
		print(e)
		return None
	finally:
		if connection:
			connection.close()
	
def paramQueryDb(query: str, params=None):
	connection = None
	try:
		connection = getDbConnection()
		with connection.cursor() as cursor:
			cursor.execute(query, params)
			return cursor.fetchone()
	except Exception as e:
		print(e)
		return None
	finally:
		if connection:
			connection.close()

def updateDb(query: str, params=None):
	connection = None
	try:
		connection = getDbConnection()
		with connection.cursor() as cursor:
			cursor.execute(query, params)
			connection.commit()
	except Exception as e:
		print(e)
	finally:
		if connection:
			connection.close()

"""
Helper function that is similar to queryDb but returns all results instead of just the first one
used for queries that return multiple rows such as the product search. 
Returns a list of dictionaries instead of just a single dictionary
"""
def selectDb(query: str, params=None):
	connection = None
	try:
		connection = getDbConnection()
		with connection.cursor() as cursor:
			cursor.execute(query, params)
			return cursor.fetchall()
	except Exception as e:
		print(e)
		return []
	finally:
		if connection:
			connection.close()


#Creating accounts and organizations
@application.route("/register")
def register():
	orgs = selectDb("SELECT Name FROM Organizations ORDER BY Name DESC", ())
	return render_template("register.html", accountType="Driver", organizations=orgs)

@application.route("/sponsorRegister")
def sRegister():
	orgs = selectDb("SELECT Name FROM Organizations ORDER BY Name DESC", ())
	return render_template("register.html", accountType="Sponsor", organizations=orgs)

@application.route("/adminRegister")
def aRegister():
	return render_template("register.html", accountType="Admin")

@application.route("/register", methods=["POST"])
def registerUser():
	sponsor = False
	organization = None
	if 'createOrg' in session:
		sponsor = True
		organization = session['createOrg']
		session.pop("createOrg", None)

	accountType = request.form.get("accType")
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

	hashPassword = generate_password_hash(password, method="pbkdf2:sha256")
	timeCreated = datetime.now()
	adminCount = queryDb("SELECT COUNT(*) as count FROM Users WHERE UserType = 'Admin'")[0] or {"count": 0}

	userType = accountType  
	if adminCount['count'] == 0:
		if accountType == "Driver" and "admin" in username.strip().lower():
			userType = "Admin"

	updateDb(
		"""INSERT INTO Users (Email, Username, Password_hash, TimeCreated, UserType, Name)
		VALUES (%s, %s, %s, %s, %s, %s)""", (email, username, hashPassword, timeCreated, userType, name))
	
	if userType == "Admin":
		newUser = paramQueryDb("SELECT UserID FROM Users WHERE Email=%s OR Username=%s", 
			(email, username))
		updateDb(
			"""INSERT INTO Admins (AdminID)
			VALUES (%s)""", (newUser['UserID']))
		flash("Admin account created please login", "created")
	else:
		if not organization:
			organization = request.form.get("organizationName")	
		orgExists = paramQueryDb("SELECT OrganizationID FROM Organizations WHERE Name = %s", (organization))
		if sponsor:
			if not orgExists:
				flash("The organization you entered doesn't exist, please enter a valid organization", "invalid")
				return redirect("sRegister")
			newUser = paramQueryDb("SELECT UserID FROM Users WHERE Email=%s OR Username=%s", 
				(email, username))		
			updateDb(
				"""INSERT INTO Sponsors (SponsorID, OrganizationName)
				VALUES (%s, %s)""", (newUser['UserID'], organization))
			flash("Sponsor account created please login", "created")
		else:	
			newUser = paramQueryDb("SELECT UserID FROM Users WHERE Email=%s OR Username=%s", 
				(email, username))
			updateDb(
				"""INSERT INTO Drivers (DriverID, OrganizationName)
				VALUES (%s, %s)""", (newUser['UserID'], organization))
			flash("Driver account created please login", "created")
	if "UserID" in session:
		return redirect(url_for("home"))
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

	updateDb(
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
			remainingTime = lockout - now
			minutesRemaining = int(remainingTime.total_seconds() // 60) + 1
			flash("Too many failed attempts. Locked for %d minutes." % minutesRemaining, "failedAttempts")
			return render_template("login.html")
		else:
			session['attempts'] = 5
			session.pop('lockoutTime', None)
	return render_template("login.html")

@application.route("/login", methods=["POST"])
def loginUser():

	session.setdefault("attempts", 5)

	if session['attempts'] <= 0:
		session['lockoutTime'] = (datetime.utcnow() + timedelta(minutes=15)).isoformat()

	if 'lockoutTime' in session:
		lockout = datetime.fromisoformat(session.get('lockoutTime'))
		now = datetime.utcnow()
		if now < lockout:
			return redirect(url_for("login"))
		else:
			session.pop('lockoutTime', None)

	identifier = request.form.get("identifier")
	exists = paramQueryDb("SELECT UserID AS id, Username, Password_hash, UserType FROM Users WHERE Email=%s OR Username=%s", 
		(identifier, identifier))

	if not exists:
		session['attempts'] -= 1
		flash("Please enter the correct credentials, Attempts left %d of 5" % (session['attempts'] + 1), "username")
		updateDb(
            """INSERT INTO Logins (LoginDate, LoginUser, LoginResult)
            VALUES (%s, %s, %s)""", (datetime.now(), "", False))
		return redirect(url_for("login"))

	password = request.form.get("password")
	hashPassword = exists["Password_hash"]

	if not check_password_hash(hashPassword, password):
		session['attempts'] -= 1
		flash("Please enter the correct credentials, Attempts left %d of 5" % (session['attempts'] + 1), "password")
		updateDb(
            """INSERT INTO Logins (LoginDate, LoginUser, LoginResult)
            VALUES (%s, %s, %s)""", (datetime.now(), identifier, False))
		return redirect(url_for("login"))

	remember = request.form.get("remember")
	if remember:
		session.permanent = True
	else:
		session.permanent = False

	session.pop('attempts', None)
	session['UserID'] = exists['id']
	session['role'] = exists['UserType']
	updateDb(
        """INSERT INTO Logins (LoginDate, LoginUser, LoginResult)
        VALUES (%s, %s, %s) """, (datetime.now(), exists['Username'], True))

	if exists['UserType'] == "Admin":
		flash("Welcome Admin, we appreciate your visit to our website!", "admin")
	elif exists['UserType'] == "Sponsor":
		flash("Welcome Sponsor, we appreciate your visit to our website!", "sponsor")
		userOrg = paramQueryDb("SELECT OrganizationName FROM Sponsors WHERE SponsorID = %s", (exists['id'],))
		session['Organization'] = userOrg['OrganizationName']
	elif exists['UserType'] == "Driver":
		flash("Welcome Driver, we appreciate your visit to our website!", "driver")
		userOrg = paramQueryDb("SELECT OrganizationName FROM Drivers WHERE SponsorID = %s", (exists['id'],))
		if userOrg:	
			session['Organization'] = userOrg['OrganizationName']

	return redirect(url_for("home"))

@application.route("/logout")
def logout():
	session.pop("UserID", None)
	session.pop("role", None)
	session.pop("attempts", None)
	session.pop("lockoutTime", None)
	return redirect(url_for("home"))

"""
Check if the user is an admin and logged in. 
If not, redirect to the login page with a flash message.
"""
def require_admin():
	if "UserID" not in session:
		flash("Please login first.", "auth")
		return redirect(url_for("login"))
	if session.get("role") != "Admin":
		flash("Admins only.", "auth")
		return redirect(url_for("home"))
	return None

def require_sponsor():
	if "UserID" not in session:
		flash("Please login first.", "auth")
		return redirect(url_for("login"))
	if session.get("role") != "Sponsor":
		flash("Sponsors only.", "auth")
		return redirect(url_for("home"))
	return None

@application.route("/admin/users")
def adminUserList():
	guard = require_admin()
	if guard: 
		return guard
	
	q = request.args.get("q", "").strip()
	like = f"%{q}%"

	if q:
		users = selectDb("""
			SELECT UserType, UserID, Username, Email, Name
			FROM Users 
			WHERE (Email LIKE %s OR Username LIKE %s OR Name = %s) AND UserID <> %s 
			ORDER BY Name
			LIMIT 50
		""", (like, like, like, session["UserID"]))
	else:
		users = selectDb("""
			SELECT UserType, UserID, Username, Email, Name
			FROM Users 
			WHERE UserID <> %s
			ORDER BY Name
			LIMIT 50
		""", (session["UserID"]))
	
	return render_template("userList.html", layout="activenav.html", users=users, q=q, accountType='admin')

@application.route("/sponsor/users")
def sponsorUserList():
	guard = require_sponsor()
	if guard:
		return guard

	q = request.args.get("q", "").strip()
	like = f"%{q}%"

	if q:
		users = selectDb("""
			SELECT UserType, UserID, Name, Email, Username
			FROM Users
			WHERE (Name LIKE %s OR Email LIKE %s OR Username LIKE %s) AND 
				  (UserType = "Sponsor" OR UserType = "Driver") AND
				  (UserID <> %s)
			ORDER BY Name
			LIMIT 50
		""", (like, like, like, session["UserID"]))
	else:
		users = selectDb("""
			SELECT UserType, UserID, Name, Email, Username
			FROM Users
			WHERE (UserType = "Sponsor" OR UserType = "Driver") AND 
				  (UserID <> %s)
			ORDER BY Name
			LIMIT 50
		""", (session["UserID"]))

	return render_template("userList.html", layout="activenav.html", users=users, q=q, accountType='sponsor')
	
@application.route("/<accountType>/users/<int:UserID>/edit")
def userEdit(accountType, UserID):
	"""if accountType == 'sponsor':
		guard = require_sponsor()
	elif accountType == 'admin':
		guard = require_admin()

	if guard:
		return guard"""

	user = paramQueryDb("""
		SELECT UserType, UserID, Name, Email, Username
		FROM Users
		WHERE UserID=%s
	""", (UserID,))
	
	if not user:
		flash("User not found.", "notfound")
		if accountType == 'sponsor':
			return redirect(url_for("sponsorUserList"))
		elif accountType == 'admin':
			return redirect(url_for("adminUserList"))

	return render_template("userEdit.html", layout="activenav.html", user=user, accountType=accountType)

@application.route("/<accountType>/users/<int:UserID>/edit", methods=["POST"])
def userEditPost(accountType, UserID):	
	"""if accountType == 'sponsor':
		guard = require_sponsor()
	elif accountType == 'admin':
		guard = require_admin()

	if guard:
		return guard"""

	name = request.form.get("name", "").strip()
	email = request.form.get("email", "").strip()
	username = request.form.get("username", "").strip()

	# basic required validation
	if not name or not email or not username:
		flash("All fields are required.", "validation")
		return redirect(url_for("userEdit", accountType=accountType, UserID=UserID))

	# uniqueness check for email/username (excluding this user)
	conflict = paramQueryDb("""
		SELECT UserID FROM Users
		WHERE (Email=%s OR Username=%s) AND UserID<>%s
	""", (email, username, UserID))

	if conflict:
		flash("Email or username already in use.", "validation")
		return redirect(url_for("userEdit", accountType=accountType, UserID=UserID))

	# update Users
	updateDb("UPDATE Users SET Name = %s, Email=%s, Username=%s WHERE UserID=%s", (name, email, username, UserID))

	flash("User profile updated.", "success")
	if accountType == "sponsor":
		return redirect(url_for("sponsorUserList"))
	elif accountType == "admin":
		return redirect(url_for("adminUserList"))
	elif accountType == "organization":
		return redirect(url_for("organizationUsers"))

@application.route("/<accountType>/users/<int:UserID>/delete", methods=["POST"])
def delete_user(accountType, UserID):
	user = paramQueryDb("SELECT UserType FROM Users WHERE UserID = %s", (UserID,))
	if user["UserType"] == "Admin": 
		updateDb("DELETE FROM Admins WHERE AdminID = %s", (UserID,))
	elif user["UserType"] == "Sponsor": 
		updateDb("DELETE FROM Sponsors WHERE SponsorID = %s", (UserID,))
	elif user["UserType"] == "Driver": 
		updateDb("DELETE FROM Drivers WHERE DriverID = %s", (UserID,))
	updateDb("DELETE FROM Users WHERE UserID = %s", (UserID,))
	
	flash("User deleted successfully.", "success")
	return redirect(f"/{accountType}")


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
	aboutInfo = queryDb("SELECT TeamNum, VersionNum, ReleaseDate, ProductName, ProductDescription FROM Admins WHERE AdminID = 1")[0]

	if not aboutInfo:
		flash("About info missing (Admins.AdminID=1).", "notfound")
		aboutInfo = {"TeamNum":"","VersionNum":"","ReleaseDate":"","ProductName":"","ProductDescription":""}
	
	if 'UserID' in session:
		return render_template("about.html", layout = "activenav.html", accountType=session['role'], Team=aboutInfo['TeamNum'], Version=aboutInfo['VersionNum'], 
			Release=aboutInfo['ReleaseDate'], Name=aboutInfo['ProductName'], Description=aboutInfo['ProductDescription'])
	return render_template("about.html", layout = "nav.html", accountType="Driver", Team=aboutInfo['TeamNum'], Version=aboutInfo['VersionNum'], 
		Release=aboutInfo['ReleaseDate'], Name=aboutInfo['ProductName'], Description=aboutInfo['ProductDescription'])

@application.route("/about/edit")
def editAbout():
	guard = require_admin()
	if guard:
		return guard
	return render_template("editAbout.html", layout="activenav.html")

@application.route("/about/edit", methods=["POST"])
def registerAboutEdits():
	guard = require_admin()
	if guard:
		return guard
	
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

	if not identifier:
		flash("No fields were provided to update.", "validation")
		return redirect(url_for("editAbout"))

	updateDb(
		f"""UPDATE Admins SET {",".join(identifier)} WHERE AdminID = 1""", update)

	return redirect(url_for("about"))

@application.route("/profile")
def profile():

	if "UserID" not in session:
		return redirect(url_for("login"))

	accountType = paramQueryDb("SELECT UserType FROM Users WHERE UserID = %s", 
		(session["UserID"],))
	if session["role"] == "Admin":
		profile = paramQueryDb("SELECT Name, Email, Username, PhoneNumber FROM Users WHERE UserID = %s", 
			(session["UserID"],))
	elif session["role"] == "Sponsor":
		profile = paramQueryDb("SELECT Name, Email, Username, PhoneNumber FROM Users WHERE UserID = %s", 
			(session["UserID"],))
	elif session["role"] == "Driver":
		profile = paramQueryDb("SELECT Name, Email, Username, PhoneNumber FROM Users WHERE UserID = %s", 
			(session["UserID"],))
	
	return render_template("profile.html", layout = "activenav.html", profile=profile)

@application.route("/profile/edit")
def editProfile():
	if "UserID" not in session:
		return redirect(url_for("login"))
	else:
		user = paramQueryDb("""
			SELECT UserType, UserID, Name, Email, Username
			FROM Users
			WHERE UserID=%s
		""", (session["UserID"],))

	return render_template("editProfile.html", user=user)

@application.route("/profile/edit", methods=["POST"])
def registerProfileEdits():
	Name = request.form.get("name")
	Username = request.form.get("username")
	Email = request.form.get("email")
	Password = request.form.get("password")

	update = []
	identifier = []

	if Username:
		identifier.append("Username = %s")
		update.append(Username)
	if Email:
		identifier.append("Email = %s")
		update.append(Email)
	if Password:
		identifier.append("Password_hash = %s")
		hashedPassword = generate_password_hash(Password)
		update.append(hashedPassword)
	if Name:
		identifier.append("Name = %s")
		update.append(Name)

	accountType = paramQueryDb("SELECT UserType FROM Users WHERE UserID = %s", 
		(session["UserID"],))

	if session["role"] == "Admin":
		updateDb(
		f"""UPDATE Users SET {",".join(identifier)} WHERE UserID = %s""", update + [session['UserID']])
	elif session["role"] == "Sponsor":
		updateDb(
		f"""UPDATE Users SET {",".join(identifier)} WHERE UserID = %s""", update + [session['UserID']])
	elif session["role"] == "Driver":
		updateDb(
		f"""UPDATE Users SET {",".join(identifier)} WHERE UserID = %s""", update + [session['UserID']])

	return redirect(url_for("profile"))

@application.route("/settings")
def settings():
	return render_template("settings.html", layout = "activenav.html") 

@application.route("/organizations")
def organizations():
	guard = require_admin()
	if guard: 
		return guard
	
	q = request.args.get("q", "").strip()
	like = f"%{q}%"

	if q:
		orgs = selectDb("""
			SELECT OrganizationID, Name
			FROM Organizations 
			WHERE Name LIKE %s
			ORDER BY Name
			LIMIT 50
		""", (like))
	else:
		orgs = selectDb("""
			SELECT OrganizationID, Name
			FROM Organizations
			ORDER BY Name
			LIMIT 50
		""")
	
	return render_template("orgList.html", layout="activenav.html", orgs=orgs, q=q)


@application.route("/organization/<int:OrgID>/edit")
def organizationEdit(OrgID):
	org = paramQueryDb("SELECT Name FROM Organizations WHERE OrganizationID = %s", (OrgID,))
	session['Organization'] = org['Name']
	return redirect(url_for("organization"))

@application.route("/organization/<int:OrgID>/delete", methods=["POST"])
def organizationDelete(OrgID):
	updateDb("DELETE FROM Organizations WHERE OrganizationID = %s", (OrgID,))
	
	flash("Organization deleted successfully.", "success")
	return redirect("/organizations")

@application.route("/organization")
def organization():
	if "Organization" in session or session.get('role') == "Admin":
		return render_template("organization.html", layout="orgnav.html", organizationName=session["Organization"])
	else:
		return render_template("organization.html", layout="orgnav.html", organizationName="None")

@application.route("/organization/users")
def organizationUsers():
	"""guard = require_admin()
	if guard: 
		return guard"""
	
	q = request.args.get("q", "").strip()
	like = f"%{q}%"

	if q:
		users = selectDb("""
			SELECT u.UserType, u.UserID, u.Name, u.Email, u.Username, s.OrganizationName, d.OrganizationName
			FROM Users u LEFT JOIN Sponsors s ON u.UserID = s.SponsorID LEFT JOIN Drivers d ON u.UserID = d.DriverID
			WHERE (Name LIKE %s OR Email LIKE %s OR Username LIKE %s) AND 
				  (UserType = "Sponsor" OR UserType = "Driver") AND 
				  (s.OrganizationName = %s OR d.OrganizationName = %s)
			ORDER BY Name
			LIMIT 50
		""", (like, like, like, session['Organization'], session['Organization']))
	else:
		users = selectDb("""
			SELECT u.UserType, u.UserID, u.Name, u.Email, u.Username, s.OrganizationName, d.OrganizationName
			FROM Users u LEFT JOIN Sponsors s ON u.UserID = s.SponsorID LEFT JOIN Drivers d ON u.UserID = d.DriverID
			WHERE (UserType = "Sponsor" OR UserType = "Driver") AND 
				  (s.OrganizationName = %s OR d.OrganizationName = %s)
			ORDER BY Name
			LIMIT 50
		""", (session['Organization'], session['Organization']))
	
	return render_template("userList.html", layout="orgnav.html", users=users, q=q, accountType='organization')

@application.route("/org_point_value")
def pointValueScreen():
	if 'UserID' in session and session["role"]=="Sponsor":
		#get org info from db
		orgName = paramQueryDb(query="SELECT OrganizationName FROM Sponsors WHERE SponsorID=%s", params=(session["UserID"]))["OrganizationName"]
		orgID = paramQueryDb(query="SELECT OrganizationID FROM Organizations WHERE Name=%s", params=(orgName))["OrganizationID"]

		#provide current point value found in db
		#later can remove try catch when point value is set on org creation
		try:
			pointVal = paramQueryDb(query="SELECT PointValue FROM Point_Values WHERE OrgID=%s", params=(orgID))["PointValue"]
		except Exception as e:
			print(e)
			pointVal = 1.00

		return render_template("point_value.html", layout="orgnav.html", current_point_value=pointVal)
	return redirect(url_for("home"))

@application.route("/point_value", methods=["POST"])
def changePointValue():
	if 'UserID' in session and session["role"]=="Sponsor":
		try:
			newPointVal = request.get_json()["newPointVal"]
			newPointVal = float(newPointVal)
			newPointVal = round(newPointVal, 2)

			#get org info from db
			orgName = paramQueryDb(query="SELECT OrganizationName FROM Sponsors WHERE SponsorID=%s", params=(session["UserID"]))["OrganizationName"]
			orgID = paramQueryDb(query="SELECT OrganizationID FROM Organizations WHERE Name=%s", params=(orgName))["OrganizationID"]

			updateDb(query="UPDATE Point_Values SET OrgID=%s, PointValue=%s", params=(orgID, newPointVal))

			return jsonify({
				"message": "Success",
				"newPointVal": newPointVal
			}), 200
		except Exception as e:
			print(e)
			return jsonify({
				"message": "Error changing value",
				"newPointVal": ""
			}), 400
	#no userID in session or not a sponsor
	return jsonify({
		"message": "Error changing value",
		"newPointVal": ""
	}), 400
		
@application.route("/point_value", methods=["GET"])
def getPointValue():
	if 'UserID' in session:
		try:
			#get org info from db
			orgName = paramQueryDb(query="SELECT OrganizationName FROM Sponsors WHERE SponsorID=%s", params=(session["UserID"]))["OrganizationName"]
			orgID = paramQueryDb(query="SELECT OrganizationID FROM Organizations WHERE Name=%s", params=(orgName))["OrganizationID"]

			#get point value tied to org
			point_value = paramQueryDb(query="SELECT PointValue FROM Point_Values WHERE OrgID=%s", params=(orgID))["PointValue"]

			#return point value
			return jsonify({
				"message": "Success",
				"pointVal": point_value
			}), 200
		except Exception as e:
			print(e)
			return jsonify({
				"message": "Error retrieving point value",
				"pointVal": ""
			}), 400

	#no userID in session
	return jsonify({
		"message": "User not signed in",
		"pointVal": ""
	}), 400

#Catalog and filtering
@application.route("/catalog")
def catalog():
	if 'UserID' in session:
		role = session.get("role")
		return render_template("catalog.html", layout="activenav.html")
	return redirect(url_for("home"))

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

"""helper function for get_products to remove products not in the given category"""
def filterByCategory(data, category):
	#will hold our data filterd based on category
	filteredData = {}
	filteredData["products"] = []

	if category == "":
		return data
	else:
		for product in data["products"]:
			if product["category"] == category:
				filteredData["products"].append(product)
		return filteredData

"""
helper function for get_products to give catalog items a point price determined
by their point worth in their org
"""
def adjustPrice(data):
	try:
		#get org info from db
		if session["role"] == "Sponsor":
			orgName = paramQueryDb(query="SELECT OrganizationName FROM Sponsors WHERE SponsorID=%s", params=(session["UserID"]))["OrganizationName"]
		elif session["role"] == "Driver":
			orgName = paramQueryDb(query="SELECT OrganizationName FROM Drivers WHERE DriverID=%s", params=(session["UserID"]))["OrganizationName"]
		orgID = paramQueryDb(query="SELECT OrganizationID FROM Organizations WHERE Name=%s", params=(orgName))["OrganizationID"]

		#get point value tied to org
		point_value = paramQueryDb(query="SELECT PointValue FROM Point_Values WHERE OrgID=%s", params=(orgID))["PointValue"]

		point_value = float(point_value)
	except Exception as e:
		point_value = 1.00

	if point_value <= 0:
		return data

	#make the price equal to the price in dollars multiplied by the point value
	#rounded to nearest whole point, always rounded up
	for product in data["products"]:
		product["price"] = math.ceil(product["price"]/float(point_value))

	return(data)

"""
remove items from product list if their id is found in the
exclusion list found in the db
"""
def removeExclusions(data):
	try:
		#get org info from db
		orgName = paramQueryDb(query="SELECT OrganizationName FROM Drivers WHERE DriverID=%s", params=(session["UserID"]))["OrganizationName"]
		orgID = paramQueryDb(query="SELECT OrganizationID FROM Organizations WHERE Name=%s", params=(orgName))["OrganizationID"]

		queryResult = queryDb(f"SELECT productID FROM Catalog_Exclusion_List WHERE orgID={orgID}")
		
		if queryResult == None:
			return data

		excludedProducts = []
		for product in queryResult:
			excludedProducts.append(product["productID"])

		filteredData = {}
		filteredData["products"] = []

		for product in data["products"]:
			if product["id"] not in excludedProducts:
				filteredData["products"].append(product)

		return filteredData
	
	#don't filter if there is an error
	except Exception as e:
		print(e)
		return data


@application.route("/get_products", methods=["POST"])
def get_products():
	url = "https://dummyjson.com/products/search?limit=300&q="
	data = request.json
	query = data["query"]
	minPrice = data["minPrice"]
	maxPrice = data["maxPrice"]
	category = data["category"]
	sortBy = data["sortBy"]
	sortDirection = data["sortDirection"]

	#change query depending on sort parameters
	if sortBy == "":
		result = requests.get(url+query)
		result = result.json()
	else: 
		result = requests.get(url+query+f"&sortBy={sortBy}&order={sortDirection}")
		result = result.json()

	if session.get("role") == "Driver":
		result = removeExclusions(result)

	#adjust dollar curreny to point currency
	result = adjustPrice(result)

	#appy category filter
	result = filterByCategory(data=result, category=category)

	#apply price filters
	result = filterByPrice(data=result, min=minPrice, max=maxPrice)

	return jsonify(result)

@application.route("/exclude_product", methods=["GET"])
def getExcludedProducts():
	userType = session.get("role")
	if "UserID" in session and userType == "Sponsor":
		try:
			#get org info from db
			orgName = paramQueryDb(query="SELECT OrganizationName FROM Sponsors WHERE SponsorID=%s", params=(session["UserID"]))["OrganizationName"]
			orgID = paramQueryDb(query="SELECT OrganizationID FROM Organizations WHERE Name=%s", params=(orgName))["OrganizationID"]

			products = queryDb(query=f"SELECT productID FROM Catalog_Exclusion_List WHERE orgID={orgID}")

			if products == None:
				return jsonify({
					"message": "No excluded products",
					"products": []
				}), 200

			#make list of product ids to send back to the javascript
			productList = []
			for product in products:
				id = product["productID"];
				productList.append(id)

			return jsonify({
				"message": "Error retrieving excluded products",
				"products": productList
			}), 200
		except Exception as e:
			print(e)
			return jsonify({
				"message": "Error retrieving excluded products",
				"products": ""
			}), 400
	return jsonify({
		"message": "Permission error",
		"products": ""
	}), 403

@application.route("/exclude_product", methods=["POST"])
def excludeProduct():
	userType = session.get("role")
	if "UserID" in session and userType == "Sponsor":
		try:
			#get org info from db
			orgName = paramQueryDb(query="SELECT OrganizationName FROM Sponsors WHERE SponsorID=%s", params=(session["UserID"]))["OrganizationName"]
			orgID = paramQueryDb(query="SELECT OrganizationID FROM Organizations WHERE Name=%s", params=(orgName))["OrganizationID"]

			#get id of product being excluded from catalog
			data = request.json
			productID = data["productID"]
			action = data["action"]

			#add product and org info to the exclusion list
			if (action == "remove"):
				updateDb("INSERT INTO Catalog_Exclusion_List (orgID, productID) VALUES (%s, %s)", params=(orgID, productID))
			elif (action == "add"):
				updateDb("DELETE FROM Catalog_Exclusion_List WHERE orgID=%s AND productID=%s", params=(orgID, productID))
			else:
				return jsonify({
					"message": "Improper action provided"
				}), 400
			
			return jsonify({
				"message": "Success"
			}), 200
		except Exception as e:
			print(e)
			return jsonify({
				"message": "Failed to update catalog"
			}), 400

	return jsonify({
		"message": "Permission error"
	}), 403

@application.route("/user/role", methods=["GET"])
def getRole():
	if "UserID" in session:
		role = session.get("role")

		#return role
		return jsonify({
			"message": "Success",
			"role": role
		}), 200
	return jsonify({
		"message": "User not signed in",
		"role": ""
	}), 400

"""
This lets us test locally. Should not execute in AWS
"""
if __name__ == "__main__":
	application.run()