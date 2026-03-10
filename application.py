from flask import Flask, render_template, redirect, url_for, request, session, flash, jsonify, Response
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
import pymysql
from config import db_config
import os
import requests
import math
import secrets
import hashlib
import csv
import io

application = Flask(__name__)
application.secret_key = os.urandom(24)  # Use a secure random key in production
application.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=1)

# -----------------------------
# Security / Validation Helpers
# -----------------------------

PASSWORD_MIN_LEN = 10
PASSWORD_MAX_LEN = 128

def password_policy_errors(pw: str):
    """Return a list of human-readable password policy errors."""
    errors = []
    if not pw:
        errors.append("Password is required.")
        return errors
    if len(pw) < PASSWORD_MIN_LEN:
        errors.append(f"Password must be at least {PASSWORD_MIN_LEN} characters.")
    if len(pw) > PASSWORD_MAX_LEN:
        errors.append(f"Password must be at most {PASSWORD_MAX_LEN} characters.")
    if not any(c.islower() for c in pw):
        errors.append("Password must include a lowercase letter.")
    if not any(c.isupper() for c in pw):
        errors.append("Password must include an uppercase letter.")
    if not any(c.isdigit() for c in pw):
        errors.append("Password must include a number.")
    if not any(not c.isalnum() for c in pw):
        errors.append("Password must include a special character.")
    return errors

def hash_reset_token(token: str) -> str:
    """Hash token before storing in DB (never store raw reset tokens)."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()

def get_user_org_id():
    """Return org id for the currently logged-in user (sponsor/driver/admin)."""
    if "Organization" not in session or not session["Organization"]:
        return None
    org = paramQueryDb("SELECT OrganizationID FROM Organizations WHERE Name=%s", (session["Organization"],))
    return org["OrganizationID"] if org else None

def get_request_ip():
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.remote_addr

def get_effective_role():
    return session.get("role")

def is_impersonating():
    return bool(session.get("impersonating"))

def get_effective_org_name():
    if session.get("Organization") and session.get("Organization") != "None":
        return session.get("Organization")
    return None

def log_password_event(event_type: str, actor_user_id=None, target_user_id=None, org_id=None):
    actor_ip = get_request_ip()
    event_time = datetime.now()

    if org_id is None and target_user_id:
        org = paramQueryDb("""
            SELECT o.OrganizationID
            FROM Users u
            LEFT JOIN Sponsors s ON u.UserID = s.SponsorID
            LEFT JOIN Drivers d ON u.UserID = d.DriverID
            LEFT JOIN Organizations o ON o.Name = COALESCE(s.OrganizationName, d.OrganizationName)
            WHERE u.UserID = %s
        """, (target_user_id,))
        if org:
            org_id = org.get("OrganizationID")

    try:
        updateDb("""
            INSERT INTO PasswordChangeLog
            (OrganizationID, ActorUserID, TargetUserID, EventType, EventTime, ActorIP)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (org_id, actor_user_id, target_user_id, event_type, event_time, actor_ip))
    except Exception as e:
        print("PasswordChangeLog insert skipped:", e)

    try:
        actor_username = None
        target_username = None

        if actor_user_id:
            actor = paramQueryDb("SELECT Username FROM Users WHERE UserID=%s", (actor_user_id,))
            actor_username = actor.get("Username") if actor else None

        if target_user_id:
            target = paramQueryDb("SELECT Username FROM Users WHERE UserID=%s", (target_user_id,))
            target_username = target.get("Username") if target else None

        if target_username:
            updateDb("""
                INSERT INTO PasswordAdjustments
                (AdjustedUName, AdjustedByUName, TypeOfChange, DateAdjusted)
                VALUES (%s, %s, %s, %s)
            """, (target_username, actor_username or target_username, event_type, event_time))
    except Exception as e:
        print("PasswordAdjustments insert skipped:", e)

def build_csv_response(filename: str, headers, rows):
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(headers)

    for row in rows:
        writer.writerow([row.get(h, "") for h in headers])

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )

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

def require_login():
    if "UserID" not in session:
        flash("Please login first.", "auth")
        return redirect(url_for("login"))
    return None

def getOrganization():
	if "UserID" in session:
		org = paramQueryDb("""SELECT o.Name, o.OrganizationID
							FROM Users u 
							LEFT JOIN Sponsors s ON u.UserID = s.SponsorID 
							LEFT JOIN Drivers d ON u.UserID = d.DriverID
							LEFT JOIN Organizations o ON o.OrganizationID=COALESCE(s.OrganizationID, d.OrganizationID)
							WHERE u.UserID = %s""", (session['UserID'],))

		if org:
			organization = org["Name"]
			if organization is not None:
				session['Organization'] = organization
				session['OrgID'] = org["OrganizationID"]
			else:
				session['Organization'] = None
				session['OrgID'] = 0
		else:
			session.pop("Organization", None)


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
	
	if 'Organization' in session and session["Organization"] != None:
		organization = session['Organization']

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
			VALUES (%s)""", (newUser['UserID'],))
		flash("Admin account created please login", "created")
	else:
		if not organization:
			organization = request.form.get("organizationName")	
		orgExists = paramQueryDb("SELECT OrganizationID FROM Organizations WHERE Name = %s", (organization,))
		if sponsor:
			if not orgExists:
				flash("The organization you entered doesn't exist, please enter a valid organization", "invalid")
				return redirect("sRegister")
			newUser = paramQueryDb("SELECT UserID FROM Users WHERE Email=%s OR Username=%s", 
				(email, username))		
			updateDb(
				"""INSERT INTO Sponsors (SponsorID, OrganizationID)
				VALUES (%s, %s)""", (newUser['UserID'], orgExists["OrganizationID"]))
			flash("Sponsor account created please login", "created")
		else:	
			newUser = paramQueryDb("SELECT UserID FROM Users WHERE Email=%s OR Username=%s", 
				(email, username))
			if not orgExists:
				updateDb(
					"""INSERT INTO Drivers (DriverID, OrganizationID)
					VALUES (%s, %s)""", (newUser['UserID'], None))
			else:
				updateDb(
					"""INSERT INTO Drivers (DriverID, OrganizationID)
					VALUES (%s, %s)""", (newUser['UserID'], orgExists["OrganizationID"]))
			flash("Driver account created please login", "created")
	if "UserID" in session:
		getOrganization()
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
	elif exists['UserType'] == "Driver":
		flash("Welcome Driver, we appreciate your visit to our website!", "driver")

	getOrganization()

	return redirect(url_for("home"))

# Forgot password
@application.route("/forgot_password")
def forgot_password():
    return render_template("forgot_password.html")

# Forgot password (POST)
@application.route("/forgot_password", methods=["POST"])
def forgot_password_post():
    email = request.form.get("email", "").strip()

    if not email:
        flash("Please enter an email.", "resetFail")
        return redirect(url_for("forgot_password"))

    # Always act the same (no account enumeration)
    user = paramQueryDb("SELECT UserID FROM Users WHERE Email=%s", (email,))
    if user:
        log_password_event("reset_requested", actor_user_id=user["UserID"], target_user_id=user["UserID"])

        raw_token = secrets.token_urlsafe(32)
        token_hash = hash_reset_token(raw_token)
        expires = datetime.now() + timedelta(minutes=30)

        updateDb("""
            INSERT INTO PasswordResetTokens
            (UserID, TokenHash, ExpiresAt, UsedAt, CreatedAt, RequestIP)
            VALUES (%s, %s, %s, NULL, %s, %s)
        """, (user["UserID"], token_hash, expires, datetime.now(), get_request_ip()))

        log_password_event("reset_issued", actor_user_id=user["UserID"], target_user_id=user["UserID"])

        # Demo-only: show reset link token
        flash(f"Reset link (demo): /reset_password/{raw_token}", "resetSent")

    flash("If an account exists for that email, reset instructions were sent.", "resetSent")
    return redirect(url_for("login"))
@application.route("/reset_password/<token>")
def reset_password(token):
    return render_template("reset_password.html", token=token)

@application.route("/reset_password/<token>", methods=["POST"])
def reset_password_post(token):
    new_pw = request.form.get("new_password", "")
    confirm = request.form.get("confirm_new_password", "")

    if new_pw != confirm:
        flash("Passwords do not match.", "resetFail")
        return redirect(url_for("reset_password", token=token))

    errors = password_policy_errors(new_pw)
    if errors:
        flash(" ".join(errors), "resetFail")
        return redirect(url_for("reset_password", token=token))

    token_hash = hash_reset_token(token)
    rec = paramQueryDb("""
        SELECT TokenID, UserID, ExpiresAt, UsedAt
        FROM PasswordResetTokens
        WHERE TokenHash=%s
    """, (token_hash,))

    if not rec or rec["UsedAt"] is not None:
        log_password_event("reset_invalid", target_user_id=rec["UserID"] if rec else None)
        flash("Reset link is invalid or already used.", "resetFail")
        return redirect(url_for("forgot_password"))

    if rec["ExpiresAt"] < datetime.now():
        log_password_event("reset_expired", actor_user_id=rec["UserID"], target_user_id=rec["UserID"])
        flash("Reset link has expired.", "resetFail")
        return redirect(url_for("forgot_password"))

    new_hash = generate_password_hash(new_pw, method="pbkdf2:sha256")
    updateDb("UPDATE Users SET Password_hash=%s WHERE UserID=%s", (new_hash, rec["UserID"]))
    updateDb("UPDATE PasswordResetTokens SET UsedAt=%s WHERE TokenID=%s", (datetime.now(), rec["TokenID"]))

    log_password_event("reset", actor_user_id=rec["UserID"], target_user_id=rec["UserID"])

    flash("Password reset successful. Please login.", "success")
    return redirect(url_for("login"))

@application.route("/logout")
def logout():
	session.pop("UserID", None)
	session.pop("role", None)
	session.pop("Organization", None)
	session.pop("attempts", None)
	session.pop("lockoutTime", None)

	session.pop("impersonating", None)
	session.pop("original_UserID", None)
	session.pop("original_role", None)
	session.pop("original_Organization", None)

	return redirect(url_for("home"))

@application.route("/admin/users")
def adminUserList():
	guard = require_admin()
	if guard: 
		return guard
	
	q = request.args.get("q", "").strip()
	like = f"%{q}%"

	page = request.args.get("page", 1, type=int)
	rowsPerPage = request.args.get("pageCount", 10, type=int)
	offset = (page - 1) * rowsPerPage

	if q:
		rowTotal = selectDb("""
			SELECT COUNT(*) AS totalRows
			FROM Users 
			WHERE (Email LIKE %s OR Username LIKE %s OR Name = %s) AND UserID <> %s 
			ORDER BY Name
		""", (like, like, like, session["UserID"]))
		users = selectDb("""
			SELECT UserType, UserID, Username, Email, Name
			FROM Users 
			WHERE (Email LIKE %s OR Username LIKE %s OR Name = %s) AND UserID <> %s 
			ORDER BY Name
			LIMIT %s OFFSET %s
		""", (like, like, like, session["UserID"],  rowsPerPage, offset))
	else:
		rowTotal = selectDb("""
			SELECT COUNT(*) AS totalRows
			FROM Users 
			WHERE UserID <> %s
			ORDER BY Name
		""", (session["UserID"],))
		users = selectDb("""
			SELECT UserType, UserID, Username, Email, Name
			FROM Users 
			WHERE UserID <> %s
			ORDER BY Name
			LIMIT %s OFFSET %s
		""", (session["UserID"], rowsPerPage, offset))

	numPages = math.ceil(rowTotal[0]["totalRows"] / rowsPerPage)
	
	return render_template("userList.html", layout="activenav.html", users=users, q=q, accountType='admin', use="website" , page=page, pageNum=range(1, numPages + 1), pageRows=rowsPerPage)

@application.route("/sponsor/users")
def sponsorUserList():
	guard = require_sponsor()
	if guard:
		return guard

	q = request.args.get("q", "").strip()
	like = f"%{q}%"

	page = request.args.get("page", 1, type=int)
	rowsPerPage = request.args.get("pageCount", 10, type=int)
	offset = (page - 1) * rowsPerPage

	if q:
		rowTotal = selectDb("""
			SELECT COUNT(*) AS totalRows
			FROM Users
			WHERE (Name LIKE %s OR Email LIKE %s OR Username LIKE %s) AND 
				  (UserType = "Sponsor" OR UserType = "Driver") AND
				  (UserID <> %s)
			ORDER BY Name
		""", (like, like, like, session["UserID"]))
		users = selectDb("""
			SELECT UserType, UserID, Name, Email, Username
			FROM Users
			WHERE (Name LIKE %s OR Email LIKE %s OR Username LIKE %s) AND 
				  (UserType = "Sponsor" OR UserType = "Driver") AND
				  (UserID <> %s)
			ORDER BY Name
			LIMIT %s OFFSET %s
		""", (like, like, like, session["UserID"], rowsPerPage, offset))
	else:
		rowTotal = selectDb("""
			SELECT COUNT(*) AS totalRows
			FROM Users
			WHERE (UserType = "Sponsor" OR UserType = "Driver") AND 
				  (UserID <> %s)
			ORDER BY Name
		""", (session["UserID"],))
		users = selectDb("""
			SELECT UserType, UserID, Name, Email, Username
			FROM Users
			WHERE (UserType = "Sponsor" OR UserType = "Driver") AND 
				  (UserID <> %s)
			ORDER BY Name
			LIMIT %s OFFSET %s
		""", (session["UserID"], rowsPerPage, offset))

	numPages = math.ceil(rowTotal[0]["totalRows"] / rowsPerPage)

	return render_template("userList.html", layout="activenav.html", users=users, q=q, accountType='sponsor', use="website", page=page, pageNum=range(1, numPages + 1), pageRows=rowsPerPage)
	
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

@application.route("/reports/<ReportType>")
def report(ReportType):
	if ReportType in ["points", "applications"]:
		if "Organization" in session and session["Organization"] != None:
			org_id = get_user_org_id()
			if not org_id:
				flash("Organization not found.", "validation")
				return redirect(url_for("home"))

	start = request.args.get("start", "").strip()
	end = request.args.get("end", "").strip()

	page = request.args.get("page", 1, type=int)
	rowsPerPage = request.args.get("pageCount", 10, type=int)
	offset = (page - 1) * rowsPerPage

	where = ""

	if ("Organization" in session and session["Organization"] != None) or start or end:
		where += "WHERE "

	if ReportType in ["points", "applications"]:
		if "Organization" in session and session["Organization"] != None:
			params = [org_id]
			if ReportType == "applications":
				where += "o.OrganizationID=%s"
			else:
				where += "OrganizationID=%s"
			if start or end:
				where += " AND "
		else:
			params = []
	else:
		params = []

	if start:
		where += "DateAdjusted >= %s"
		params.append(start + " 00:00:00")
		if end:
			where += " AND "
	if end:
		where += "DateAdjusted <= %s"
		params.append(end + " 23:59:59")

	if ReportType == "passwords":
		rowTotal = selectDb(f"""
			SELECT COUNT(*) AS totalRows
			FROM PasswordAdjustments pa
			JOIN Users u ON u.Username = pa.AdjustedUName
			JOIN Users x ON x.Username = pa.AdjustedByUName
			{where}
			ORDER BY pa.DateAdjusted DESC
			""", tuple(params))
		params.append(rowsPerPage)
		params.append(offset)
		rows = selectDb(f"""
			SELECT pa.DateAdjusted, pa.TypeOfChange,
				x.Name AS ActorName,
				u.Name AS TargetName
			FROM PasswordAdjustments pa
			JOIN Users u ON u.Username = pa.AdjustedUName
			JOIN Users x ON x.Username = pa.AdjustedByUName
			{where}
			ORDER BY pa.DateAdjusted DESC
			LIMIT %s OFFSET %s
			""", tuple(params))
	elif ReportType == "points":
		rowTotal = selectDb(f"""
			SELECT COUNT(*) AS totalRows
			FROM PointAdjustments
			{where}
			ORDER BY DateAdjusted DESC
			""", tuple(params))
		params.append(rowsPerPage)
		params.append(offset)
		rows = selectDb(f"""
			SELECT DriverUName, AdjustedByUName, AdjustmentType, AdjustmentPoints, AdjustmentReason, DateAdjusted
			FROM PointAdjustments
			{where}
			ORDER BY DateAdjusted DESC
			LIMIT %s OFFSET %s
			""", tuple(params))
	elif ReportType == "applications":
		rowTotal = selectDb(f"""
			SELECT COUNT(*) AS totalRows
			FROM OrganizationApplications a
			JOIN Organizations o ON a.OrganizationID = o.OrganizationID
			{where}
			ORDER BY DateApplied DESC
			""", tuple(params))
		params.append(rowsPerPage)
		params.append(offset)
		rows = selectDb(f"""
			SELECT a.DriverUName, a.ReviewedByUName, a.ApplicationStatus, a.ReviewReason, a.DateApplied, o.Name
			FROM OrganizationApplications a
			JOIN Organizations o ON a.OrganizationID = o.OrganizationID
			{where}
			ORDER BY DateApplied DESC
			LIMIT %s OFFSET %s
			""", tuple(params))
	elif ReportType == "logins":
		rowTotal = selectDb(f"""
			SELECT COUNT(*) AS totalRows
			FROM Logins
			{where}
			ORDER BY LoginDate DESC
			""", tuple(params))
		params.append(rowsPerPage)
		params.append(offset)
		rows = selectDb(f"""
			SELECT LoginDate, LoginUser, 
			CASE
				WHEN LoginResult = 1 THEN "Successful Login"
				WHEN LoginResult = 0 THEN "Failed Login"
			END AS LoginStatus
			FROM Logins
			{where}
			ORDER BY LoginDate DESC
			LIMIT %s OFFSET %s
			""", tuple(params))

	numPages = math.ceil(rowTotal[0]["totalRows"] / rowsPerPage)

	if session.get("role") == "Admin" and session.get("Organization") == None:
		nav = "activenav.html"
	elif session.get("role") == "Admin" and session.get("Organization") != None:
		nav = "orgnav.html"
	else:
		nav = "orgnav.html"

	return render_template("logReports.html", layout=nav, rows=rows, start=start, end=end, ReportType=ReportType, page=page, pageNum=range(1, numPages + 1), pageRows=rowsPerPage)

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
def deleteUser(accountType, UserID):
	user = paramQueryDb("SELECT UserType FROM Users WHERE UserID = %s", (UserID,))
	if user["UserType"] == "Admin": 
		updateDb("DELETE FROM Admins WHERE AdminID = %s", (UserID,))
	elif user["UserType"] == "Sponsor": 
		updateDb("DELETE FROM Sponsors WHERE SponsorID = %s", (UserID,))
	elif user["UserType"] == "Driver": 
		updateDb("DELETE FROM Drivers WHERE DriverID = %s", (UserID,))
	updateDb("DELETE FROM Users WHERE UserID = %s", (UserID,))
	
	flash("User deleted successfully.", "success")
	return redirect(f"/{accountType}/users")


#The different website pages
@application.route("/")
def home():
	if 'UserID' in session:
		getOrganization()
		if session.get("Organization") != None and session.get("Role") == "Admin":
			session["Organization"]	= None		
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
    if "UserID" not in session:
        return redirect(url_for("login"))

    Name = request.form.get("name", "").strip()
    Username = request.form.get("username", "").strip()
    Email = request.form.get("email", "").strip()
    PhoneNumber = request.form.get("phoneNum", "").strip()

    # NEW security fields
    CurrentPassword = request.form.get("currentPassword", "")
    NewPassword = request.form.get("newPassword", "")
    ConfirmNewPassword = request.form.get("confirmNewPassword", "")

    # Fetch current user record
    user = paramQueryDb("""
        SELECT UserID, Name, Email, Username, PhoneNumber, Password_hash
        FROM Users
        WHERE UserID=%s
    """, (session["UserID"],))

    if not user:
        flash("User not found.", "validation")
        return redirect(url_for("profile"))

    update_fields = []
    update_vals = []

    # Uniqueness checks (only if changed)
    if Username and Username != user["Username"]:
        exists = paramQueryDb("SELECT UserID FROM Users WHERE Username=%s AND UserID<>%s",
                             (Username, session["UserID"]))
        if exists:
            flash("That username is already taken.", "username")
            return redirect(url_for("editProfile"))
        update_fields.append("Username=%s")
        update_vals.append(Username)

    if Email and Email != user["Email"]:
        exists = paramQueryDb("SELECT UserID FROM Users WHERE Email=%s AND UserID<>%s",
                             (Email, session["UserID"]))
        if exists:
            flash("That email is already in use.", "email")
            return redirect(url_for("editProfile"))

        # Require current password for email change
        if not CurrentPassword or not check_password_hash(user["Password_hash"], CurrentPassword):
            flash("Current password is required to change email.", "password")
            return redirect(url_for("editProfile"))

        update_fields.append("Email=%s")
        update_vals.append(Email)

    if Name and Name != user["Name"]:
        update_fields.append("Name=%s")
        update_vals.append(Name)

    if PhoneNumber != (user.get("PhoneNumber") or ""):
        # allow blank to clear
        update_fields.append("PhoneNumber=%s")
        update_vals.append(PhoneNumber if PhoneNumber else None)

    # Password change (requires current password)
    if NewPassword or ConfirmNewPassword:
        if not CurrentPassword or not check_password_hash(user["Password_hash"], CurrentPassword):
            flash("Current password is required to change password.", "password")
            return redirect(url_for("editProfile"))

        errors = password_policy_errors(NewPassword)
        if errors:
            flash(" ".join(errors), "passwordErrors")
            return redirect(url_for("editProfile"))

        if NewPassword != ConfirmNewPassword:
            flash("New password and confirmation do not match.", "confirmPassword")
            return redirect(url_for("editProfile"))


        update_fields.append("Password_hash=%s")
        update_vals.append(generate_password_hash(NewPassword, method="pbkdf2:sha256"))

        # Log password change event
        updateDb("""
            INSERT INTO PasswordAdjustments (AdjustedUName, AdjustedByUName, TypeOfChange, DateAdjusted)
            VALUES (%s, %s, %s, %s)
        """, (user.get("Username"), user.get("Username"), "change", datetime.now()))

    if not update_fields:
        flash("No changes detected.", "validation")
        return redirect(url_for("editProfile"))

    updateDb(
        f"UPDATE Users SET {', '.join(update_fields)} WHERE UserID=%s",
        tuple(update_vals + [session["UserID"]])
    )

    flash("Profile updated.", "success")
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
	
	page = request.args.get("page", 1, type=int)
	rowsPerPage = request.args.get("pageCount", 10, type=int)
	offset = (page - 1) * rowsPerPage

	if q:
		rowTotal = selectDb("""
			SELECT COUNT(*) AS totalRows
			FROM Organizations 
			WHERE Name LIKE %s
			ORDER BY Name
		""", (like,))
		orgs = selectDb("""
			SELECT OrganizationID, Name
			FROM Organizations 
			WHERE Name LIKE %s
			ORDER BY Name
			LIMIT %s OFFSET %s
		""", (like, rowsPerPage, offset))
	else:
		rowTotal = selectDb("""
			SELECT COUNT(*) AS totalRows
			FROM Organizations
			ORDER BY Name
		""")
		orgs = selectDb("""
			SELECT OrganizationID, Name
			FROM Organizations
			ORDER BY Name
			LIMIT %s OFFSET %s
		""", (rowsPerPage, offset))

	numPages = math.ceil(rowTotal[0]["totalRows"] / rowsPerPage)
	
	return render_template("orgList.html", layout="activenav.html", orgs=orgs, q=q, page=page, pageNum=range(1, numPages + 1), pageRows=rowsPerPage)

@application.route("/organizations/<int:OrgID>/view")
def organizationView(OrgID):
    org = paramQueryDb("SELECT Name FROM Organizations WHERE OrganizationID = %s", (OrgID,))
    session['Organization'] = org['Name']
    return redirect(url_for("organization"))

@application.route("/organizations/<int:OrgID>/edit", methods=["POST"])
def organizationEdit(OrgID):
	newName = request.form.get("newName")
	updateDb("UPDATE Organizations SET Name = %s WHERE OrganizationID = %s", (newName, OrgID))
	return redirect(url_for("organizations"))

@application.route("/organizations/<int:OrgID>/delete", methods=["POST"])
def organizationDelete(OrgID):
	updateDb("UPDATE Drivers SET OrganizationID = %s WHERE OrganizationID = %s", ("0", OrgID))
	updateDb("DELETE FROM Organizations WHERE OrganizationID = %s", (OrgID,))
	
	flash("Organization deleted successfully.", "success")
	return redirect(url_for("organizations"))

@application.route("/organization")
def organization():
	getOrganization()
	if ("Organization" in session and session["Organization"] != None) or session.get('role') == "Admin":
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

	page = request.args.get("page", 1, type=int)
	rowsPerPage = request.args.get("pageCount", 10, type=int)
	offset = (page - 1) * rowsPerPage

	if q:
		rowTotal = selectDb("""
			SELECT COUNT(*) AS totalRows
			FROM Users u LEFT JOIN Sponsors s ON u.UserID = s.SponsorID 
			LEFT JOIN Drivers d ON u.UserID = d.DriverID
			LEFT JOIN Organizations o ON o.OrganizationID=COALESCE(s.OrganizationID, d.OrganizationID)
			WHERE (u.Name LIKE %s OR u.Email LIKE %s OR u.Username LIKE %s) AND 
				  (u.UserType = "Sponsor" OR u.UserType = "Driver") AND 
				  (o.Name = %s)
			ORDER BY o.Name
		""", (like, like, like, session['Organization']))
		users = selectDb("""
			SELECT u.UserID, u.UserType, u.UserID, u.Name, u.Email, u.Username, o.Name, d.TotalPoints
			FROM Users u LEFT JOIN Sponsors s ON u.UserID = s.SponsorID 
			LEFT JOIN Drivers d ON u.UserID = d.DriverID
			LEFT JOIN Organizations o ON o.OrganizationID=COALESCE(s.OrganizationID, d.OrganizationID)
			WHERE (u.Name LIKE %s OR u.Email LIKE %s OR u.Username LIKE %s) AND 
				  (u.UserType = "Sponsor" OR u.UserType = "Driver") AND 
				  (o.Name = %s)
			ORDER BY o.Name
			LIMIT %s OFFSET %s
		""", (like, like, like, session['Organization'], rowsPerPage, offset))
	else:
		rowTotal = selectDb("""
			SELECT COUNT(*) AS totalRows
			FROM Users u LEFT JOIN Sponsors s ON u.UserID = s.SponsorID 
			LEFT JOIN Drivers d ON u.UserID = d.DriverID
			LEFT JOIN Organizations o ON o.OrganizationID=COALESCE(s.OrganizationID, d.OrganizationID)
			WHERE (u.UserType = "Sponsor" OR u.UserType = "Driver") AND 
				  (o.Name = %s)
			ORDER BY o.Name
		""", (session['Organization'],))
		users = selectDb("""
			SELECT u.UserID, u.UserType, u.UserID, u.Name, u.Email, u.Username, o.Name, d.TotalPoints
			FROM Users u LEFT JOIN Sponsors s ON u.UserID = s.SponsorID 
			LEFT JOIN Drivers d ON u.UserID = d.DriverID
			LEFT JOIN Organizations o ON o.OrganizationID=COALESCE(s.OrganizationID, d.OrganizationID)
			WHERE (u.UserType = "Sponsor" OR u.UserType = "Driver") AND 
				  (o.Name = %s)
			ORDER BY o.Name
			LIMIT %s OFFSET %s
		""", (session['Organization'], rowsPerPage, offset))

	numPages = math.ceil(rowTotal[0]["totalRows"] / rowsPerPage)
	
	return render_template("userList.html", layout="orgnav.html", users=users, q=q, accountType='organization', use="organization", page=page, pageNum=range(1, numPages + 1), pageRows=rowsPerPage)

@application.route("/organization/users/<int:UserID>/points")
def adjustDriverPoints(UserID):
    guard = require_sponsor()
    if guard:
    # allow Admin too
        if session.get("role") != "Admin":
            return guard

    driver = paramQueryDb("""
        SELECT u.UserID, u.Name AS DriverName, u.Email, u.Username, o.Name AS OrgName, d.TotalPoints
        FROM Users u
        JOIN Drivers d ON u.UserID = d.DriverID
		JOIN Organization o ON d.OrganizationID = o.OrganizationID
        WHERE u.UserID=%s AND u.UserType='Driver'
    """, (UserID,))

    if not driver:
        flash("Driver not found.", "notfound")
        return redirect(url_for("organizationUsers"))

    return render_template("adjustDriverPoints.html", layout="orgnav.html", driver=driver)

@application.route("/organization/users/<int:UserID>/points", methods=["POST"])
def adjustDriverPointsPost(UserID):
	guard = require_sponsor()
	if guard:
    # allow Admin too
		if session.get("role") != "Admin":
			return guard
			
    # Read + validate inputs
	adjustmentType = request.form.get("adjustType")
	pointsRaw = request.form.get("points", "").strip()
	reason = request.form.get("reason", "").strip()

	if not pointsRaw.isdigit():
		flash("Points must be a positive integer.", "validation")
		return redirect(url_for("adjustDriverPoints", UserID=UserID))

	points = int(pointsRaw)
	if points <= 0:
		flash("Points must be greater than 0.", "validation")
		return redirect(url_for("adjustDriverPoints", UserID=UserID))

	if not reason:
		flash("Reason/feedback is required.", "validation")
		return redirect(url_for("adjustDriverPoints", UserID=UserID))

	# Fetch current points
	driver = paramQueryDb("""
		SELECT u.UserID, u.Username, d.TotalPoints
		FROM Users u
		JOIN Drivers d ON u.UserID = d.DriverID
		WHERE u.UserID=%s AND u.UserType='Driver'
		""", (UserID,))

	if not driver:
		flash("Driver not found.", "notfound")
		return redirect(url_for("organizationUsers"))

	currentPoints = int(driver.get("TotalPoints") or 0)
	if adjustmentType == "Award":
		newTotal = currentPoints + points
	elif adjustmentType == "Deduct":
		newTotal = currentPoints - points
		if newTotal < 0:
			newTotal = 0  # clamp (or change to block if your rules require)

	# Update driver points
	updateDb("UPDATE Drivers SET TotalPoints=%s WHERE DriverID=%s", (newTotal, UserID))

	# Try to record feedback in an audit table if it exists (won't crash if not)
	user = paramQueryDb("""SELECT Username FROM Users WHERE UserID = %s""", (session["UserID"],))
	organization = paramQueryDb("""SELECT OrganizationID FROM Organizations WHERE Name = %s""", (session["Organization"],))
	try:
		updateDb("""
		INSERT INTO PointAdjustments(OrganizationID, AdjustedByUName, DriverUName, AdjustmentType, AdjustmentPoints, AdjustmentReason, DateAdjusted)
		VALUES (%s, %s, %s, %s, %s, %s)
		""", (organization.get("OrganizationID"), user.get("Username"), driver["Username"], adjustmentType, points, reason, datetime.now()))
	except Exception as e:
		# If table doesn't exist, keep app working
		print("PointDeductions insert skipped:", e)

	flash(f"Adjusted Points by {points}. New total: {newTotal}.", "success")
	return redirect(url_for("organizationUsers"))

@application.route("/organization/users/<int:UserID>/remove", methods=["POST"])
def removeOrgUser(UserID):
	user = selectDb("""SELECT UserType FROM Users WHERE UserID = %s""", (UserID,))
	if user[0]["UserType"] == "Sponsor":
		updateDb("""UPDATE Sponsors SET OrganizationID = 0 WHERE SponsorID = %s""", (UserID,))
	elif user[0]["UserType"] == "Driver":
		updateDb("""UPDATE Drivers SET OrganizationID = 0 WHERE DriverID = %s""", (UserID,))
	return redirect(url_for("organizationUsers"))

@application.route("/organization/apply")
def apply():
	user = selectDb("SELECT Username FROM Users WHERE UserID = %s", (session["UserID"],))
	username = user[0]["Username"]
	orgs = selectDb("SELECT OrganizationID, Name FROM Organizations ORDER BY Name DESC", ())
	application = selectDb("""SELECT o.Name, a.ApplicationStatus 
							FROM OrganizationApplications a JOIN Organizations o ON a.OrganizationID = o.OrganizationID
							WHERE a.DriverUName = %s and a.ApplicationStatus = %s""", (username, "Pending"))
	if application:
		app = application[0]
	else:
		app = None
	return render_template("enroll.html", layout="activenav.html", orgs=orgs, application=app)
	
@application.route("/organization/leave", methods=["POST"])
def organization_leave():
    if "UserID" not in session:
        flash("Please login first.", "auth")
        return redirect(url_for("login"))

    if session.get("role") != "Driver":
        flash("Drivers only.", "auth")
        return redirect(url_for("organization"))

    updateDb(
        "UPDATE Drivers SET OrganizationID=%s WHERE DriverID=%s",
        (None, session["UserID"])
    )

    session.pop("Organization", None)
    flash("You left the organization.", "success")
    return redirect(url_for("home"))

@application.route("/organization/apply", methods=["POST"])
def applyPost():
	organization = request.form.get("organization")
	user = paramQueryDb("""SELECT Username FROM Users WHERE UserID = %s""", (session['UserID'],))
	org = paramQueryDb("""SELECT OrganizationID FROM Organizations WHERE Name = %s""", (organization,))
	timeApplied = datetime.now()
	updateDb("""INSERT INTO OrganizationApplications (OrganizationID, DriverUName, ApplicationStatus, DateApplied)
				VALUES (%s, %s, %s, %s)""", (org["OrganizationID"], user['Username'], "Pending", timeApplied))
	flash(f"You have applied for enrollment in { organization } ", "enrolled")
	return redirect(url_for("apply"))

@application.route("/organization/apply/cancel")
def cancelPost():
	user = paramQueryDb("""SELECT u.Username, a.OrganizationID 
						FROM Users u JOIN OrganizationApplications a ON u.Username = a.DriverUName 
						WHERE UserID = %s""", (session['UserID'],))
	updateDb("""DELETE FROM OrganizationApplications WHERE DriverUName = %s AND OrganizationID = %s""", (user["Username"], user["OrganizationID"]))
	return redirect(url_for("apply"))

@application.route("/organization/applications")
def applications():
	q = request.args.get("q", "").strip()
	like = f"%{q}%"

	page = request.args.get("page", 1, type=int)
	rowsPerPage = request.args.get("pageCount", 10, type=int)
	offset = (page - 1) * rowsPerPage

	if q:
		rowTotal = selectDb("""
			SELECT COUNT(*) AS totalRows
			FROM OrganizationApplications a JOIN Users u ON a.DriverUName = u.Username JOIN Organizations o ON a.OrganizationID = o.OrganizationID
			WHERE (u.Name LIKE %s OR u.Email LIKE %s OR u.Username LIKE %s) AND 
					(u.UserType = "Driver") AND (o.Name = %s) AND a.ApplicationStatus = "Pending"
			ORDER BY o.Name, u.Name
			""", (like, like, like, session['Organization']))
		users = selectDb("""
			SELECT u.UserID, u.Username, u.Name, u.Email, u.UserType, a.DateApplied, o.Name
			FROM OrganizationApplications a JOIN Users u ON a.DriverUName = u.Username JOIN Organizations o ON a.OrganizationID = o.OrganizationID
			WHERE (u.Name LIKE %s OR u.Email LIKE %s OR u.Username LIKE %s) AND 
					(u.UserType = "Driver") AND (o.Name = %s) AND a.ApplicationStatus = "Pending"
			ORDER BY o.Name, u.Name
			LIMIT %s OFFSET %s
			""", (like, like, like, session['Organization'], rowsPerPage, offset))
	else:
		rowTotal = selectDb("""
			SELECT COUNT(*) AS totalRows
			FROM OrganizationApplications a JOIN Users u ON a.DriverUName = u.Username JOIN Organizations o ON a.OrganizationID = o.OrganizationID
			WHERE (u.UserType = "Driver") AND (o.Name = %s) AND a.ApplicationStatus = "Pending"
			ORDER BY o.Name, u.Name
			""", (session['Organization'],))
		users = selectDb("""
			SELECT u.UserID, u.Username, u.Name, u.Email, u.UserType, a.DateApplied, o.Name
			FROM OrganizationApplications a JOIN Users u ON a.DriverUName = u.Username JOIN Organizations o ON a.OrganizationID = o.OrganizationID
			WHERE (u.UserType = "Driver") AND (o.Name = %s) AND a.ApplicationStatus = "Pending"
			ORDER BY o.Name, u.Name
			LIMIT %s OFFSET %s
			""", (session['Organization'], rowsPerPage, offset))

	numPages = math.ceil(rowTotal[0]["totalRows"] / rowsPerPage)

	return render_template("userList.html", layout="orgnav.html", users=users, q=q, accountType='organization', use="application", page=page, pageNum=range(1, numPages + 1), pageRows=rowsPerPage)

@application.route("/organization/applications/<int:UserID>/accept", methods=["POST"])
def acceptedApplications(UserID):
	reason = request.form.get("acceptReason")
	user = paramQueryDb("""SELECT Username FROM Users WHERE UserID = %s""", (session['UserID'],))
	driver = paramQueryDb("""SELECT Username FROM Users WHERE UserID = %s""", (UserID,))
	timeJoined= datetime.now()
	updateDb("""UPDATE OrganizationApplications SET ApplicationStatus = %s, ReviewedByUName = %s, ReviewReason = %s WHERE DriverUName = %s""", ("Accepted", user["Username"], reason, driver["Username"]))
	updateDb("""UPDATE Drivers SET OrganizationID = %s, DateJoined = %s WHERE DriverID = %s""", (session['OrgID'], timeJoined, UserID))
	return redirect(url_for("applications"))

@application.route("/organization/applications/<int:UserID>/reject", methods=["POST"])
def rejectedApplications(UserID):
	reason = request.form.get("rejectReason")
	user = paramQueryDb("""SELECT Username FROM Users WHERE UserID = %s""", (session['UserID'],))
	driver = paramQueryDb("""SELECT Username FROM Users WHERE UserID = %s""", (UserID,))
	updateDb("""UPDATE OrganizationApplications SET ApplicationStatus = %s, ReviewedByUName = %s, ReviewReason = %s WHERE DriverUName = %s""", ("Rejected", user["Username"], reason, driver["Username"]))
	return redirect(url_for("applications"))

@application.route("/organization/point_value")
def pointValueScreen():
	if 'UserID' in session and session.get("role")=="Sponsor":
		#get org info from db
		#orgName = paramQueryDb(query="SELECT OrganizationName FROM Sponsors WHERE SponsorID=%s", params=(session["UserID"]))["OrganizationName"]
		#orgID = paramQueryDb(query="SELECT OrganizationID FROM Organizations WHERE Name=%s", params=(orgName))["OrganizationID"]

		#provide current point value found in db
		#later can remove try catch when point value is set on org creation
		try:
			pointVal = paramQueryDb(query="SELECT PointValue FROM Point_Values WHERE OrgID=%s", params=(session["OrgID"]))["PointValue"]
		except Exception as e:
			print(e)
			pointVal = 1.00

		return render_template("point_value.html", layout="orgnav.html", current_point_value=pointVal)
	return redirect(url_for("home"))

@application.route("/point_value", methods=["POST"])
def changePointValue():
	if 'UserID' in session and session.get("role")=="Sponsor":
		try:
			newPointVal = request.get_json()["newPointVal"]
			newPointVal = float(newPointVal)
			newPointVal = round(newPointVal, 2)

			#get org info from db
			#orgName = paramQueryDb(query="SELECT OrganizationName FROM Sponsors WHERE SponsorID=%s", params=(session["UserID"]))["OrganizationName"]
			#orgID = paramQueryDb(query="SELECT OrganizationID FROM Organizations WHERE Name=%s", params=(orgName))["OrganizationID"]

			updateDb(query="UPDATE Point_Values SET OrgID=%s, PointValue=%s", params=(session["OrgID"], newPointVal))

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
			#orgName = paramQueryDb(query="SELECT OrganizationName FROM Sponsors WHERE SponsorID=%s", params=(session["UserID"]))["OrganizationName"]
			#orgID = paramQueryDb(query="SELECT OrganizationID FROM Organizations WHERE Name=%s", params=(orgName))["OrganizationID"]

			#get point value tied to org
			point_value = paramQueryDb(query="SELECT PointValue FROM Point_Values WHERE OrgID=%s", params=(session["OrgID"]))["PointValue"]

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

@application.route("/catalog/rules")
def catalogRules():
	if 'UserID' in session and session.get("role")=="Sponsor":
		#get org info for user
		#orgName = paramQueryDb(query="SELECT OrganizationName FROM Sponsors WHERE SponsorID=%s", params=(session.get("UserID")))["OrganizationName"]
		#orgID = paramQueryDb(query="SELECT OrganizationID FROM Organizations WHERE Name=%s", params=(orgName))["OrganizationID"]
		orgID = session["OrgID"]

		#get data from Catalog_Rules
		try:
			getRuleQuery = """
				SELECT * 
				FROM Catalog_Rules
				WHERE orgID=%s
			"""
			ruleData = paramQueryDb(query=getRuleQuery, params=(orgID))
			rules = {
				'minPoints': ruleData.get('minPoints'), 
				'maxPoints': ruleData.get('maxPoints'), 
				'minRating': ruleData.get('minRating'), 
			}
		except Exception as e:
			print(e)
			rules = {
				'minPoints': None, 
				'maxPoints': None, 
				'minRating': None
			}

		#get data from Allowed_Categories
		try:
			getCategoriesQuery = f"""
				SELECT *
				FROM Allowed_Categories
				WHERE orgID={orgID}
			"""

			categoryData = queryDb(getCategoriesQuery)

			#collect all allowed categories in an array
			allowedCategories = []
			for row in categoryData:
				allowedCategories.append(row.get("category"))

		except Exception as e:
			print(e)
			allowedCategories = ["keep-all"]

		#get data from Allowed_Brands
		try:
			getBrandsQuery = f"""
				SELECT *
				FROM Allowed_Brands
				WHERE orgID={orgID}
			"""

			brandData = queryDb(getBrandsQuery)

			#collect all allowed brands into an array
			allowedBrands = []
			for row in brandData:
				allowedBrands.append(row.get("brand"))

		except Exception as e:
			print(e)
			allowedBrands = ["keep-all"]

		return render_template("catalog_rules.html", layout="orgnav.html", orgName=session["Organization"], rules=rules, allowedCategories=allowedCategories, allowedBrands=allowedBrands)
	return redirect(url_for("home"))


"""
Where sponsors connect to when submitting catalog rules form
"""
@application.route("/catalog/rules", methods=["POST"])
def changeCatalogRules():
	if 'UserID' in session and session.get("role")=="Sponsor":
		#get org info from db
		#orgName = paramQueryDb(query="SELECT OrganizationName FROM Sponsors WHERE SponsorID=%s", params=(session["UserID"]))["OrganizationName"]
		#orgID = paramQueryDb(query="SELECT OrganizationID FROM Organizations WHERE Name=%s", params=(orgName))["OrganizationID"]
		orgID = session["OrgID"]

		minPoints = request.form.get("min-price")
		maxPoints = request.form.get("max-price")
		minRating = request.form.get("min-rating")
		keepAllCategories = request.form.get("keep-all-categories")
		keepAllBrands = request.form.get("keep-all-brands")
		allowedCategories = request.form.getlist("category")
		allowedBrands = request.form.getlist("brand")

		#do we have a rule yet for this org?
		ruleCount = paramQueryDb(query="SELECT COUNT(1) FROM Catalog_Rules WHERE orgID=%s", params=(orgID))["COUNT(1)"]
		orgHasRule = ruleCount>0

		#make empty strings None for db queries
		def makeNoneIfEmpty(var):
			return None if var=="" else var
		minPoints = makeNoneIfEmpty(minPoints)
		maxPoints = makeNoneIfEmpty(maxPoints)
		minRating = makeNoneIfEmpty(minRating)

		#update rule if present, otherwise insert new rule
		if ruleCount>0:
			updateDb(query="UPDATE Catalog_Rules SET minPoints=%s, maxPoints=%s, minRating=%s, updated=current_timestamp WHERE orgID=%s", params=(minPoints, maxPoints, minRating, orgID))
		else:
			updateDb(query="INSERT INTO Catalog_Rules (orgID, minPoints, maxPoints, minRating, created) VALUES (%s, %s, %s, %s, current_timestamp)", params=(orgID, minPoints, maxPoints, minRating))

		clearCategoriesQuery = "DELETE FROM Allowed_Categories WHERE orgID=%s"

		clearBrandsQuery = "DELETE FROM Allowed_Brands WHERE orgID=%s"

		addCategoryQuery = "INSERT INTO Allowed_Categories (orgID, category) VALUES (%s, %s)"

		addBrandQuery = "INSERT INTO Allowed_Brands (orgID, brand) VALUES (%s, %s)"
		
		#table logic for allowed categories
		if keepAllCategories == "keep-all":
			#clear allowed categories
			updateDb(query=clearCategoriesQuery, params=(orgID))
			#insert keep-all value
			updateDb(query=addCategoryQuery, params=(orgID, keepAllCategories))
		elif allowedCategories != []:
			#clear allowed categories
			updateDb(query=clearCategoriesQuery, params=(orgID))
			#insert each allowed category
			for category in allowedCategories:
				updateDb(query=addCategoryQuery, params=(orgID, category))
		else:
			#clear allowed categories
			updateDb(query=clearCategoriesQuery, params=(orgID))
			updateDb(query=addCategoryQuery, params=(orgID, "none"))

		#table logic for allowed brands
		if keepAllBrands == "keep-all":
			#clear allowed brands
			updateDb(query=clearBrandsQuery, params=(orgID))
			#insert keep-all value
			updateDb(query=addBrandQuery, params=(orgID, keepAllBrands))
		elif allowedBrands != []:
			#clear allowed brands
			updateDb(query=clearBrandsQuery, params=(orgID))
			for brand in allowedBrands:
				updateDb(query=addBrandQuery, params=(orgID, brand))
		else:
			#clear allowed brands
			updateDb(query=clearBrandsQuery, params=(orgID))
			updateDb(query=addBrandQuery, params=(orgID, "none"))

		return redirect(url_for("catalogRules"))
	return redirect(url_for("catalogRules"))

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
		#if session["role"] == "Sponsor":
		#	orgName = paramQueryDb(query="SELECT OrganizationName FROM Sponsors WHERE SponsorID=%s", params=(session["UserID"]))["OrganizationName"]
		#elif session["role"] == "Driver":
		#	orgName = paramQueryDb(query="SELECT OrganizationName FROM Drivers WHERE DriverID=%s", params=(session["UserID"]))["OrganizationName"]
		#orgID = paramQueryDb(query="SELECT OrganizationID FROM Organizations WHERE Name=%s", params=(orgName))["OrganizationID"]
		orgID = session["OrgID"]

		#get point value tied to org
		point_value = paramQueryDb(query="SELECT PointValue FROM Point_Values WHERE OrgID=%s", params=(orgID))["PointValue"]

		point_value = float(point_value)
	except Exception as e:
		point_value = 1.00

	if point_value <= 0:
		return data

	#make the price equal to the price in dollars multiplied by the point value
	#rounded to nearest whole point, always rounded up
	if "products" in data:
		for product in data["products"]:
			product["price"] = math.ceil(product["price"]/float(point_value))
	else:
		for product in data:
			product["price"] = math.ceil(product["price"]/float(point_value))

	return(data)

"""
remove items from product list if their id is found in the
exclusion list found in the db
"""
def removeExclusions(data):
	try:
		#get org info from db
		#orgName = paramQueryDb(query="SELECT OrganizationName FROM Drivers WHERE DriverID=%s", params=(session["UserID"]))["OrganizationName"]
		#orgID = paramQueryDb(query="SELECT OrganizationID FROM Organizations WHERE Name=%s", params=(orgName))["OrganizationID"]
		orgID = session["OrgID"]

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

"""
Removes any products from a list of products that fall below the given rating
"""
def filterByRating(data, minRating:float):

	if minRating == None or minRating == "":
		return data
	
	minRating = float(minRating)
	
	filteredData = {}
	filteredData["products"] = []

	productList = data.get("products")

	for item in productList:
		if float(item.get("rating")) >= minRating:
			filteredData["products"].append(item)

	return filteredData

"""
Removes any products from a list of products that do not belong to the allowed
categories list.
"""
def filterByAllowedCategories(data):
	try:
		#get session data for queries
		userType = session.get("role")
		userID = session.get("UserID")

		#get organization name from specific user table
		#getOrgNameQuery = f"""
		#	SELECT OrganizationName
		#	FROM {userType}s
		#	WHERE {userType}ID = %s
		#"""
		#orgName = paramQueryDb(query=getOrgNameQuery, params=(userID)).get("OrganizationName")

		#get organization ID from Organizations table
		#getOrgIDQuery = """
		#	SELECT OrganizationID
		#	FROM Organizations
		#	WHERE Name=%s
		#"""
		#orgID = paramQueryDb(query=getOrgIDQuery, params=(orgName)).get("OrganizationID")
		orgID = session["OrgID"]

		getAllowedCategoriesQuery = f"""
			SELECT category
			FROM Allowed_Categories
			WHERE orgID={orgID}
		"""
		rows = queryDb(getAllowedCategoriesQuery)
		
		allowedCategories = []
		for row in rows:
			allowedCategories.append(row.get("category"))

		#filter by category
		filteredData = {}
		filteredData["products"] = []

		for product in data.get("products"):
			if product.get("category") in allowedCategories or "keep-all" in allowedCategories:
				filteredData["products"].append(product)

		return filteredData

	except Exception as e:
		print(e)
		return data
	

"""
Removes any products from a list of products that do not belong to the allowed
brands list.
"""
def filterByAllowedBrands(data):
	try:
		#get session data for queries
		userType = session.get("role")
		userID = session.get("UserID")

		#get organization name from specific user table
		#getOrgNameQuery = f"""
		#	SELECT OrganizationName
		#	FROM {userType}s
		#	WHERE {userType}ID = %s
		#"""
		#orgName = paramQueryDb(query=getOrgNameQuery, params=(userID)).get("OrganizationName")

		#get organization ID from Organizations table
		#getOrgIDQuery = """
		#	SELECT OrganizationID
		#	FROM Organizations
		#	WHERE Name=%s
		#"""
		#orgID = paramQueryDb(query=getOrgIDQuery, params=(orgName)).get("OrganizationID")
		orgID = session["OrgID"]

		getAllowedBrandsQuery = f"""
			SELECT brand
			FROM Allowed_Brands
			WHERE orgID={orgID}
		"""
		rows = queryDb(getAllowedBrandsQuery)
		
		allowedBrands = []
		for row in rows:
			allowedBrands.append(row.get("brand"))

		#filter by brand
		filteredData = {}
		filteredData["products"] = []

		for product in data.get("products"):
			if product.get("brand") in allowedBrands or "keep-all" in allowedBrands:
				filteredData["products"].append(product)

		return filteredData

	except Exception as e:
		print(e)
		return data

"""
Helper function for get_products. Filters out products based on catalog 
rules set for the organization.
"""
def filterByRules(data):
	try:
		#get session data for queries
		userType = session.get("role")
		userID = session.get("UserID")

		#get organization name from specific user table
		#getOrgNameQuery = f"""
		#	SELECT OrganizationName
		#	FROM {userType}s
		#	WHERE {userType}ID = %s
		#"""
		#orgName = paramQueryDb(query=getOrgNameQuery, params=(userID)).get("OrganizationName")

		#get organization ID from Organizations table
		#getOrgIDQuery = """
		#	SELECT OrganizationID
		#	FROM Organizations
		#	WHERE Name=%s
		#"""
		#orgID = paramQueryDb(query=getOrgIDQuery, params=(orgName)).get("OrganizationID")
		orgID = session["OrgID"]

		#get catalog rules for organization
		try:
			getRulesQuery = """
				SELECT *
				FROM Catalog_Rules
				WHERE orgID=%s
			"""
			rules = paramQueryDb(query=getRulesQuery, params=(orgID))

			minPoints = rules.get("minPoints")
			maxPoints = rules.get("maxPoints")
			minRating = rules.get("minRating")

			data = filterByPrice(data=data, min=minPoints, max=maxPoints)
			data = filterByRating(data=data, minRating=minRating)
			data = filterByAllowedCategories(data=data)
			data = filterByAllowedBrands(data=data)

		except Exception as e:
			pass

		return data
		
	except Exception as e:
		print(e)
		return data

"""
gives a boolean flag to mark a product as either being in a user's wishlist or not
"""
def markWishlistedProducts(products):
	#retrieve product ids of wishlisted items from the db
	wishlist = []
	try:
		userID = session.get("UserID")
		getWishlistQuery = f"""
			SELECT *
			FROM Wishlist
			WHERE userID={userID}
		"""
		rows = queryDb(getWishlistQuery)
		
		for row in rows:
			wishlist.append(row.get("productID"))
	except Exception as e:
		print(e)
		return products
	
	for product in products.get("products"):
		if product.get("id") in wishlist:
			product["wishlisted"] = True
		else:
			product["wishlisted"] = False

	return products


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

	#remove any products from product exclusion list table
	if session.get("role") == "Driver":
		result = removeExclusions(result)

	#adjust dollar curreny to point currency
	result = adjustPrice(result)

	#filter products based on catalog rules
	result = filterByRules(result)

	#appy category filter
	result = filterByCategory(data=result, category=category)

	#apply price filters
	result = filterByPrice(data=result, min=minPrice, max=maxPrice)

	#give flag to products that are wishlisted
	result = markWishlistedProducts(result)

	return jsonify(result)

@application.route("/exclude_product", methods=["GET"])
def getExcludedProducts():
	userType = session.get("role")
	if "UserID" in session and userType == "Sponsor":
		try:
			#get org info from db
			#orgName = paramQueryDb(query="SELECT OrganizationName FROM Sponsors WHERE SponsorID=%s", params=(session["UserID"]))["OrganizationName"]
			#orgID = paramQueryDb(query="SELECT OrganizationID FROM Organizations WHERE Name=%s", params=(orgName))["OrganizationID"]
			orgID = session["OrgID"]

			products = queryDb(query=f"SELECT productID FROM Catalog_Exclusion_List WHERE orgID={orgID}")

			if products == None:
				return jsonify({
					"message": "No excluded products",
					"products": []
				}), 200

			#make list of product ids to send back to the javascript
			productList = []
			for product in products:
				id = product["productID"]
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
			#orgName = paramQueryDb(query="SELECT OrganizationName FROM Sponsors WHERE SponsorID=%s", params=(session["UserID"]))["OrganizationName"]
			#orgID = paramQueryDb(query="SELECT OrganizationID FROM Organizations WHERE Name=%s", params=(orgName))["OrganizationID"]
			orgID = session["OrgID"]

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

@application.route("/wishlist/add", methods=["POST"])
def addToWishList():
	if "UserID" in session and session.get("role")=="Driver":
		productData = request.json
		productID = productData.get("productID")

		userID = session.get("UserID")

		#orgName = paramQueryDb(query="SELECT OrganizationName FROM Drivers WHERE DriverID=%s", params=(userID)).get("OrganizationName")
		#orgID = paramQueryDb(query="SELECT OrganizationID FROM Organizations WHERE Name=%s", params=(orgName)).get("OrganizationID")
		orgID = session["OrgID"]

		insertWishlistProductQuery = """
			INSERT INTO Wishlist
			(userID, productID, orgID)
			VALUES (%s, %s, %s)
		"""
		try:
			updateDb(query=insertWishlistProductQuery, params=(userID, productID, orgID))
		except Exception as e:
			print(e)
			return jsonify({
				"message": "Database query error"
			}), 400


		return jsonify({
			"message": "Success"
		}), 200
	else:
		return jsonify({
			"message": "Permission error"
		}), 400

@application.route("/wishlist/remove", methods=["POST"])
def removeFromWishList():
	if "UserID" in session and session.get("role")=="Driver":
		productData = request.json
		productID = productData.get("productID")

		userID = session.get("UserID")

		#orgName = paramQueryDb(query="SELECT OrganizationName FROM Drivers WHERE DriverID=%s", params=(userID)).get("OrganizationName")
		#orgID = paramQueryDb(query="SELECT OrganizationID FROM Organizations WHERE Name=%s", params=(orgName)).get("OrganizationID")
		orgID = session.get("OrgID")

		deleteFromWishlistQuery = """
			DELETE FROM Wishlist
			WHERE 
				userID=%s
				AND productID=%s
				AND orgID=%s
		"""
		try:
			updateDb(query=deleteFromWishlistQuery, params=(userID, productID, orgID))
		except Exception as e:
			print(e)
			return jsonify({
				"message": "Database query error"
			}), 400


		return jsonify({
			"message": "Success"
		}), 200
	else:
		return jsonify({
			"message": "Permission error"
		}), 400

@application.route("/wishlist")
def wishlist():
	if "UserID" in session and session.get("role")=="Driver":
		#get data needed for queries
		userID = session.get("UserID")
		orgName = session.get("Organization")

		#get orgID from Organizations table
		try:
			getOrgIDQuery = """
				SELECT OrganizationID
				FROM Organizations
				WHERE Name=%s
			"""
			orgID = paramQueryDb(query=getOrgIDQuery, params=(orgName)).get("OrganizationID")
		except Exception as e:
			print(f"Problem with getOrgIDQuery in wishlist function: {e}")
			orgID = None

		try:
			getWishlistQuery = f"""
				SELECT productID
				FROM Wishlist
				WHERE
					userID={userID}
					AND orgID={orgID}
			"""
			rows = queryDb(query=getWishlistQuery) or []

			wishlistProductIDs = []
			for row in rows:
				wishlistProductIDs.append(row.get("productID"))
		except Exception as e:
			print(f"Issue with retrieving wishlist product ids in wishlist(): {e}")
			wishlistProductIDs = []

		#query the dummy json api to retrieve their product information
		if len(wishlistProductIDs)<1:
			return render_template("wishlist.html", layout="activenav.html", wishlistData=[])

		api_url = "https://dummyjson.com/products/?limit=300"
		response = requests.get(api_url)

		if response.status_code != 200:
			return render_template("wishlist.html", layout="activenav.html", wishlistData=[])

		productData = response.json().get("products")

		#collect the product data into one list to send into the html
		wishlistData = []
		for product in productData:
			if product.get("id") in wishlistProductIDs:
				wishlistData.append(product)

		wishlistData = adjustPrice(wishlistData)

		return render_template("wishlist.html", layout="activenav.html", wishlistData=wishlistData)
	return redirect(url_for("home"))

@application.route("/cart/add", methods=["POST"])
def addToCart():
	if "UserID" in session:
		userID = session.get("UserID")
		orgID = session.get("OrgID")
		productID = request.json.get("productID")

		try:
			addToCartQuery = """
				INSERT INTO Cart
				(userID, orgID, productID, amount)
				VALUES (%s, %s, %s, %s)
			"""
			updateDb(query=addToCartQuery, params=(userID, orgID, productID, 1))
		except Exception as e:
			print(f"Issue with query in '/car/add': {e}")
			return jsonify({"message": "Issue updating cart"}), 400
		
		return jsonify({"message": "Success"}), 200
	return jsonify({"message": "Permission error"}), 400
"""
This lets us test locally. Should not execute in AWS
"""
if __name__ == "__main__":

	application.run()