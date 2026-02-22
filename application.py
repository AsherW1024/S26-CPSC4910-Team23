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
		return results[0] if results else None
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

def insertDb(query: str, params=None):
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
	return render_template("register.html", accountType="Driver")

@application.route("/sponsorRegister")
def sRegister():
	return render_template("register.html", accountType="Sponsor")

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
	adminCount = queryDb("SELECT COUNT(*) as count FROM Users WHERE UserType = 'a'") or {"count": 0}
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
		if not organization:
			organization = request.form.get("organizationName")	
		orgExists = paramQueryDb("SELECT OrganizationID FROM Organizations WHERE Name = %s", (organization))
		if sponsor:
			if not orgExists:
				flash("The organization you entered doesn't exist, please enter a valid organization", "invalid")
				return redirect("sRegister")
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
		insertDb(
            """INSERT INTO Logins (LoginDate, LoginUser, LoginResult)
            VALUES (%s, %s, %s)""", (datetime.now(), "", False))
		return redirect(url_for("login"))

	password = request.form.get("password")
	hashPassword = exists["Password_hash"]

	if not check_password_hash(hashPassword, password):
		session['attempts'] -= 1
		flash("Please enter the correct credentials, Attempts left %d of 5" % (session['attempts'] + 1), "password")
		insertDb(
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
	insertDb(
        """INSERT INTO Logins (LoginDate, LoginUser, LoginResult)
        VALUES (%s, %s, %s) """, (datetime.now(), exists['Username'], True))

	if exists['UserType'] == 'a':
		flash("Welcome Admin, we appreciate your visit to our website!", "admin")
	elif exists['UserType'] == 's':
		flash("Welcome Sponsor, we appreciate your visit to our website!", "sponsor")
		userOrg = paramQueryDb("SELECT OrganizationName FROM Sponsors WHERE SponsorID = %s", (exists['id']))
		session['Organization'] = userOrg['OrganizationName']
	elif exists['UserType'] == 'd':
		flash("Welcome Driver, we appreciate your visit to our website!", "driver")
		userOrg = paramQueryDb("SELECT OrganizationName FROM Drivers WHERE SponsorID = %s", (exists['id']))
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
	if session.get("role") != "a":
		flash("Admins only.", "auth")
		return redirect(url_for("home"))
	return None

def require_sponsor():
	if "UserID" not in session:
		flash("Please login first.", "auth")
		return redirect(url_for("login"))
	if session.get("role") != "s":
		flash("Sponsors only.", "auth")
		return redirect(url_for("home"))
	return None

@application.route("/admin/sponsors")
def admin_sponsor_list():
	guard = require_admin()
	if guard: 
		return guard

	q = request.args.get("q", "").strip()
	like = f"%{q}%"

	if q:
		sponsors = selectDb("""
			SELECT u.UserID, s.Name, u.Email, u.Username, s.OrganizationName
			FROM Users u
			JOIN Sponsors s ON u.UserID = s.SponsorID
			WHERE u.UserType='s'
			  AND (s.Name LIKE %s OR u.Email LIKE %s OR u.Username LIKE %s OR s.OrganizationName LIKE %s)
			ORDER BY s.Name
			LIMIT 50
		""", (like, like, like, like))
	else:
		sponsors = selectDb("""
			SELECT u.UserID, s.Name, u.Email, u.Username, s.OrganizationName
			FROM Users u
			JOIN Sponsors s ON u.UserID = s.SponsorID
			WHERE u.UserType='s'
			ORDER BY s.Name
			LIMIT 50
		""")

	return render_template("admin_sponsor_list.html", layout="activenav.html", sponsors=sponsors, q=q)

@application.route("/admin/sponsors/<int:sponsor_id>/edit")
def admin_sponsor_edit(sponsor_id):
	guard = require_admin()
	if guard:
		return guard

	sponsor = paramQueryDb("""
		SELECT u.UserID, s.Name, u.Email, u.Username, s.OrganizationName
		FROM Users u
		JOIN Sponsors s ON u.UserID = s.SponsorID
		WHERE u.UserID=%s AND u.UserType='s'
	""", (sponsor_id,))

	if not sponsor:
		flash("Sponsor not found.", "notfound")
		return redirect(url_for("admin_sponsor_list"))

	return render_template("admin_sponsor_edit.html", layout="activenav.html", sponsor=sponsor)

@application.route("/admin/sponsors/<int:sponsor_id>/edit", methods=["POST"])
def admin_sponsor_edit_post(sponsor_id):
	guard = require_admin()
	if guard:
		return guard

	name = request.form.get("name", "").strip()
	email = request.form.get("email", "").strip()
	username = request.form.get("username", "").strip()
	org = request.form.get("organization", "").strip()

	# basic required validation
	if not name or not email or not username or not org:
		flash("All fields are required.", "validation")
		return redirect(url_for("admin_sponsor_edit", sponsor_id=sponsor_id))

	# uniqueness check for email/username (excluding this user)
	conflict = paramQueryDb("""
		SELECT UserID FROM Users
		WHERE (Email=%s OR Username=%s) AND UserID<>%s
	""", (email, username, sponsor_id))

	if conflict:
		flash("Email or username already in use.", "validation")
		return redirect(url_for("admin_sponsor_edit", sponsor_id=sponsor_id))

	# update Users + Sponsors
	insertDb("UPDATE Users SET Email=%s, Username=%s WHERE UserID=%s", (email, username, sponsor_id))
	insertDb("UPDATE Sponsors SET Name=%s, OrganizationName=%s WHERE SponsorID=%s", (name, org, sponsor_id))

	flash("Sponsor profile updated.", "success")
	return redirect(url_for("admin_sponsor_list"))

@application.route("/admin/drivers")
def admin_driver_list():
	guard = require_admin()
	if guard:
		return guard

	q = request.args.get("q", "").strip()
	like = f"%{q}%"

	if q:
		drivers = selectDb("""
			SELECT u.UserID, d.Name, u.Email, u.Username, d.OrganizationName
			FROM Users u
			JOIN Drivers d ON u.UserID = d.DriverID
			WHERE u.UserType='d'
			  AND (d.Name LIKE %s OR u.Email LIKE %s OR u.Username LIKE %s OR d.OrganizationName LIKE %s)
			ORDER BY d.Name
			LIMIT 50
		""", (like, like, like, like))
	else:
		drivers = selectDb("""
			SELECT u.UserID, d.Name, u.Email, u.Username, d.OrganizationName
			FROM Users u
			JOIN Drivers d ON u.UserID = d.DriverID
			WHERE u.UserType='d'
			ORDER BY d.Name
			LIMIT 50
		""")

	return render_template("admin_driver_list.html", layout="activenav.html", drivers=drivers, q=q)

@application.route("/admin/drivers/<int:driver_id>/edit")
def admin_driver_edit(driver_id):
	guard = require_admin()
	if guard:
		return guard

	driver = paramQueryDb("""
		SELECT u.UserID, d.Name, u.Email, u.Username, d.OrganizationName
		FROM Users u
		JOIN Drivers d ON u.UserID = d.DriverID
		WHERE u.UserID=%s AND u.UserType='d'
	""", (driver_id,))

	if not driver:
		flash("Driver not found.", "notfound")
		return redirect(url_for("admin_driver_list"))

	return render_template("admin_driver_edit.html", layout="activenav.html", driver=driver)

@application.route("/admin/drivers/<int:driver_id>/edit", methods=["POST"])
def admin_driver_edit_post(driver_id):
	guard = require_admin()
	if guard:
		return guard

	name = request.form.get("name", "").strip()
	email = request.form.get("email", "").strip()
	username = request.form.get("username", "").strip()
	org = request.form.get("organization", "").strip()

	if not name or not email or not username or not org:
		flash("All fields are required.", "validation")
		return redirect(url_for("admin_driver_edit", driver_id=driver_id))

	conflict = paramQueryDb("""
		SELECT UserID FROM Users
		WHERE (Email=%s OR Username=%s) AND UserID<>%s
	""", (email, username, driver_id))

	if conflict:
		flash("Email or username already in use.", "validation")
		return redirect(url_for("admin_driver_edit", driver_id=driver_id))

	insertDb("UPDATE Users SET Email=%s, Username=%s WHERE UserID=%s", (email, username, driver_id))
	insertDb("UPDATE Drivers SET Name=%s, OrganizationName=%s WHERE DriverID=%s", (name, org, driver_id))

	flash("Driver profile updated.", "success")
	return redirect(url_for("admin_driver_list"))

@application.route("/sponsor/drivers")
def sponsor_driver_list():
	guard = require_sponsor()
	if guard:
		return guard

	q = request.args.get("q", "").strip()
	like = f"%{q}%"

	if q:
		drivers = selectDb("""
			SELECT u.UserID, d.Name, u.Email, u.Username, d.OrganizationName
			FROM Users u
			JOIN Drivers d ON u.UserID = d.DriverID
			WHERE u.UserType='d'
			  AND (d.Name LIKE %s OR u.Email LIKE %s OR u.Username LIKE %s OR d.OrganizationName LIKE %s)
			ORDER BY d.Name
			LIMIT 50
		""", (like, like, like, like))
	else:
		drivers = selectDb("""
			SELECT u.UserID, d.Name, u.Email, u.Username, d.OrganizationName
			FROM Users u
			JOIN Drivers d ON u.UserID = d.DriverID
			WHERE u.UserType='d'
			ORDER BY d.Name
			LIMIT 50
		""")

	return render_template("sponsor_driver_list.html", layout="activenav.html", drivers=drivers, q=q)

@application.route("/sponsor/drivers/<int:driver_id>/edit")
def sponsor_driver_edit(driver_id):
	guard = require_sponsor()
	if guard:
		return guard

	driver = paramQueryDb("""
		SELECT u.UserID, d.Name, u.Email, u.Username, d.OrganizationName
		FROM Users u
		JOIN Drivers d ON u.UserID = d.DriverID
		WHERE u.UserID=%s AND u.UserType='d'
	""", (driver_id,))

	if not driver:
		flash("Driver not found.", "notfound")
		return redirect(url_for("admin_driver_list"))

	return render_template("sponsor_driver_edit.html", layout="activenav.html", driver=driver)

@application.route("/sponsor/drivers/<int:driver_id>/edit", methods=["POST"])
def sponsor_driver_edit_post(driver_id):
	guard = require_sponsor()
	if guard:
		return guard

	name = request.form.get("name", "").strip()
	email = request.form.get("email", "").strip()
	username = request.form.get("username", "").strip()
	org = request.form.get("organization", "").strip()

	if not name or not email or not username or not org:
		flash("All fields are required.", "validation")
		return redirect(url_for("admin_driver_edit", driver_id=driver_id))

	conflict = paramQueryDb("""
		SELECT UserID FROM Users
		WHERE (Email=%s OR Username=%s) AND UserID<>%s
	""", (email, username, driver_id))

	if conflict:
		flash("Email or username already in use.", "validation")
		return redirect(url_for("admin_driver_edit", driver_id=driver_id))

	insertDb("UPDATE Users SET Email=%s, Username=%s WHERE UserID=%s", (email, username, driver_id))
	insertDb("UPDATE Drivers SET Name=%s, OrganizationName=%s WHERE DriverID=%s", (name, org, driver_id))

	flash("Driver profile updated.", "success")
	return redirect(url_for("sponsor_driver_list"))

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

	if not aboutInfo:
		flash("About info missing (Admins.AdminID=1).", "notfound")
		aboutInfo = {"TeamNum":"","VersionNum":"","ReleaseDate":"","ProductName":"","ProductDescription":""}
	
	if 'UserID' in session:
		return render_template("about.html", layout = "activenav.html", accountType=session['role'], Team=aboutInfo['TeamNum'], Version=aboutInfo['VersionNum'], 
			Release=aboutInfo['ReleaseDate'], Name=aboutInfo['ProductName'], Description=aboutInfo['ProductDescription'])
	return render_template("about.html", layout = "nav.html", accountType='d', Team=aboutInfo['TeamNum'], Version=aboutInfo['VersionNum'], 
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

@application.route("/profile/edit")
def editProfile():
	return render_template("editProfile.html")

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

	accountType = paramQueryDb("SELECT UserType FROM Users WHERE UserID = %s", 
		(session["UserID"],))

	if session["role"] == "a":
		insertDb(
		f"""UPDATE Users SET {",".join(identifier)} WHERE UserID = %s""", update + [session['UserID']])
		if Name:
			insertDb(
			f"""UPDATE Admins SET Name = %s WHERE AdminID = %s""", [Name] + [session['UserID']])
	elif session["role"] == "s":
		insertDb(
		f"""UPDATE Users SET {",".join(identifier)} WHERE UserID = %s""", update + [session['UserID']])
		if Name:
			insertDb(
			f"""UPDATE Sponsors SET Name = %s WHERE SponsorID = %s""", [Name] + [session['UserID']])
	elif session["role"] == "d":
		insertDb(
		f"""UPDATE Users SET {",".join(identifier)} WHERE UserID = %s""", update + [session['UserID']])
		if Name:
			insertDb(
			f"""UPDATE Drivers SET Name = %s WHERE DriverID = %s""", [Name] + [session['UserID']])

	return redirect(url_for("profile"))

@application.route("/settings")
def settings():
	return render_template("settings.html", layout = "activenav.html") 

@application.route("/org_point_value")
def pointValueScreen():
	if 'UserID' in session and session["role"]=="s":
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

		return render_template("point_value.html", layout="activenav.html", current_point_value=pointVal)
	return redirect(url_for("home"))

@application.route("/point_value", methods=["POST"])
def changePointValue():
	if 'UserID' in session and session["role"]=="s":
		try:
			newPointVal = request.get_json()["newPointVal"]
			newPointVal = float(newPointVal)
			newPointVal = round(newPointVal, 2)

			#get org info from db
			orgName = paramQueryDb(query="SELECT OrganizationName FROM Sponsors WHERE SponsorID=%s", params=(session["UserID"]))["OrganizationName"]
			orgID = paramQueryDb(query="SELECT OrganizationID FROM Organizations WHERE Name=%s", params=(orgName))["OrganizationID"]

			insertDb(query="UPDATE Point_Values SET OrgID=%s, PointValue=%s", params=(orgID, newPointVal))

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
		orgName = paramQueryDb(query="SELECT OrganizationName FROM Sponsors WHERE SponsorID=%s", params=(session["UserID"]))["OrganizationName"]
		orgID = paramQueryDb(query="SELECT OrganizationID FROM Organizations WHERE Name=%s", params=(orgName))["OrganizationID"]

		#get point value tied to org
		point_value = paramQueryDb(query="SELECT PointValue FROM Point_Values WHERE OrgID=%s", params=(orgID))["PointValue"]
	except Exception as e:
		print(e)
		return data

	#make the price equal to the price in dollars multiplied by the point value
	#rounded to nearest whole point, always rounded up
	for product in data["products"]:
		product["price"] = math.ceil(product["price"]*float(point_value))

	return(data)

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

	#adjust dollar curreny to point currency
	result = adjustPrice(result)

	#appy category filter
	result = filterByCategory(data=result, category=category)

	#apply price filters
	result = filterByPrice(data=result, min=minPrice, max=maxPrice)

	return jsonify(result)

"""
This lets us test locally. Should not execute in AWS
"""
if __name__ == "__main__":
	application.run()