from flask import Flask, render_template, redirect, url_for, request, session, flash, jsonify, Response
from functools import wraps
from datetime import datetime, timedelta
from urllib.parse import urlencode
from werkzeug.security import generate_password_hash, check_password_hash
import pymysql
from config import db_config
import os
import requests
import math
import secrets
import hashlib
import base64
import csv
import io
from datetime import date
from cryptography.fernet import Fernet, InvalidToken

application = Flask(__name__)
application.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-change-me-secret-key")
application.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=1)
application.config['SESSION_COOKIE_HTTPONLY'] = True
application.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
application.config['SESSION_COOKIE_SECURE'] = os.environ.get('FLASK_ENV') == 'production'

IDLE_TIMEOUT_MINUTES = int(os.environ.get('IDLE_TIMEOUT_MINUTES', 20))
IDLE_WARNING_MINUTES = int(os.environ.get('IDLE_WARNING_MINUTES', 5))
LOGIN_MAX_ATTEMPTS = int(os.environ.get('LOGIN_MAX_ATTEMPTS', 5))
LOGIN_LOCKOUT_MINUTES = int(os.environ.get('LOGIN_LOCKOUT_MINUTES', 15))
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

def is_impersonating():
    return bool(session.get("impersonating"))

def get_effective_org_name():
    org = session.get("Organization")
    return org if org not in (None, "None", "") else None

def get_org_name_for_user(user_id):
    row = paramQueryDb("""
        SELECT o.Name AS OrganizationName
        FROM Users u
        LEFT JOIN Sponsors s ON u.UserID = s.SponsorID
        LEFT JOIN DriverOrganizations d ON u.UserID = d.DriverID
        LEFT JOIN Organizations o ON o.OrganizationID = COALESCE(s.OrganizationID, d.OrganizationID)
        WHERE u.UserID = %s
    """, (user_id,))
    return row.get("OrganizationName") if row else None

def log_password_event(event_type: str, actor_user_id=None, target_user_id=None):
    event_time = datetime.now()

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
def format_currency(value):
    try:
        return f"{float(value):.2f}"
    except Exception:
        return "0.00"


def parse_iso_date(raw_value):
    if not raw_value:
        return None
    try:
        return datetime.strptime(raw_value, "%Y-%m-%d").date()
    except ValueError:
        return None

def getDriverData():
	rows = selectDb("SELECT * FROM Users WHERE UserType = 'Driver'")
	return rows

def getOrgData():
	rows = selectDb("""SELECT * FROM Organizations""")
	return rows

def get_sales_by_product_rows(org_id=None, start=None, end=None, rowsPerPage=None, offset=None):
    count_query = """
        SELECT
            COUNT(DISTINCT oi.productID) AS totalRows
        FROM OrderItems oi
        JOIN Orders o ON o.orderID = oi.orderID
    """
    base_query = """
        SELECT
            oi.productID,
            COUNT(DISTINCT o.orderID) AS orderCount,
            SUM(oi.amount) AS quantitySold,
            SUM(oi.totalPrice) AS grossSales
        FROM OrderItems oi
        JOIN Orders o ON o.orderID = oi.orderID
    """
    params = []
    where_clauses = []

    if org_id:
        where_clauses.append("o.orgID = %s")
        params.append(org_id)

    if start:
        where_clauses.append("orderTime >= %s")
        params.append(start + " 00:00:00")

    if end:
        where_clauses.append("orderTime <= %s")
        params.append(end + " 23:59:59")

    if where_clauses:
        count_query += " WHERE " + " AND ".join(where_clauses)
        base_query += " WHERE " + " AND ".join(where_clauses)

    base_query += """
        GROUP BY oi.productID
        ORDER BY grossSales DESC, quantitySold DESC
		LIMIT %s OFFSET %s
    """
	
    rowTotal = selectDb(count_query, tuple(params)) or [{"totalRows": 0}]
    rows = selectDb(base_query, tuple(list(params) + [rowsPerPage, offset])) or []

    total_rows = rowTotal[0]["totalRows"] if rowTotal else 0 
    numPages = max(1, math.ceil(total_rows / rowsPerPage)) if rowsPerPage else 1

    enriched_rows = []
    for row in rows:
        product_id = row.get("productID")
        try:
            product_data = getProductData(product_id) or {}
        except Exception:
            product_data = {}

        enriched_rows.append({
            "productID": product_id,
            "productName": product_data.get("title") or f"Product {product_id}",
            "category": product_data.get("category") or "",
            "brand": product_data.get("brand") or "",
            "orderCount": row.get("orderCount") or 0,
            "quantitySold": row.get("quantitySold") or 0,
            "grossSales": float(row.get("grossSales") or 0)
        })

    return enriched_rows, numPages

def get_refund_cancellation_impact_rows(org_id=None):
    base_query = """
        SELECT
            o.orderID,
            o.orgID,
            o.pointTotal,
            o.orderTime,
            COALESCE(MAX(CASE WHEN osa.StatusName='Refunded' THEN 1 ELSE 0 END), 0) AS isRefunded,
            COALESCE(MAX(CASE WHEN osa.StatusName='Cancelled' THEN 1 ELSE 0 END), 0) AS isCancelled
        FROM Orders o
        LEFT JOIN OrderStatusAudit osa ON osa.OrderID = o.orderID
    """
    params = []
    where_clauses = []

    if org_id:
        where_clauses.append("o.orgID = %s")
        params.append(org_id)

    if where_clauses:
        base_query += " WHERE " + " AND ".join(where_clauses)

    base_query += """
        GROUP BY o.orderID, o.orgID, o.pointTotal, o.orderTime
        ORDER BY o.orderTime DESC
    """

    rows = selectDb(base_query, tuple(params)) or []

    summary = {
        "grossSales": 0.0,
        "refundTotal": 0.0,
        "cancelledTotal": 0.0,
        "netSales": 0.0
    }

    detailed_rows = []
    for row in rows:
        point_total = float(row.get("pointTotal") or 0)
        is_refunded = int(row.get("isRefunded") or 0) == 1
        is_cancelled = int(row.get("isCancelled") or 0) == 1

        summary["grossSales"] += point_total
        if is_refunded:
            summary["refundTotal"] += point_total
        if is_cancelled:
            summary["cancelledTotal"] += point_total

        status = "Completed"
        if is_refunded:
            status = "Refunded"
        elif is_cancelled:
            status = "Cancelled"

        detailed_rows.append({
            "orderID": row.get("orderID"),
            "orgID": row.get("orgID"),
            "pointTotal": point_total,
            "status": status,
            "orderTime": row.get("orderTime")
        })

    summary["netSales"] = summary["grossSales"] - summary["refundTotal"] - summary["cancelledTotal"]
    return summary, detailed_rows

def get_invoice_rows(fee_rate=0.01, start=None, end=None, rowsPerPage=None, offset=None):
	count_query = """
        SELECT
            COUNT(DISTINCT o.orgID) AS totalRows
        FROM Orders o
        LEFT JOIN Organizations org ON org.OrganizationID = o.orgID
    """
	base_query = """
        SELECT
            o.orgID,
            org.Name AS OrganizationName,
            COUNT(DISTINCT o.orderID) AS orderCount,
            SUM(o.pointTotal) AS salesTotal
        FROM Orders o
        LEFT JOIN Organizations org ON org.OrganizationID = o.orgID
    """
	params = []
	where_clauses = []

	if start:
		where_clauses.append("orderTime >= %s")
		params.append(start + " 00:00:00")

	if end:
		where_clauses.append("orderTime <= %s")
		params.append(end + " 23:59:59")

	if where_clauses:
		count_query += " WHERE " + " AND ".join(where_clauses)
		base_query += " WHERE " + " AND ".join(where_clauses)

	base_query += """
        GROUP BY o.orgID, org.Name
        ORDER BY salesTotal DESC
		LIMIT %s OFFSET %s
    """

	rowTotal = selectDb(count_query, tuple(params)) or [{"totalRows": 0}]
	rows = selectDb(base_query, tuple(list(params) + [rowsPerPage, offset])) or []

	total_rows = rowTotal[0]["totalRows"] if rowTotal else 0
	numPages = max(1, math.ceil(total_rows / rowsPerPage)) if rowsPerPage else 1

	invoice_rows = []
	for row in rows:
		sales_total = float(row.get("salesTotal") or 0)
		fee_amount = round(sales_total * fee_rate, 2)
		invoice_rows.append({
			"orgID": row.get("orgID"),
			"organizationName": row.get("OrganizationName") or f"Organization {row.get('orgID')}",
			"orderCount": row.get("orderCount") or 0,
			"salesTotal": sales_total,
			"feeRate": fee_rate,
			"feeAmount": fee_amount,
			"invoiceTotal": round(sales_total + fee_amount, 2),
			"feeExplanation": f"{int(fee_rate * 100)}% fee applied to sales total"
		})
	return invoice_rows, numPages

def get_about_info():
    rows = queryDb("SELECT TeamNum, VersionNum, ReleaseDate, ProductName, ProductDescription FROM Admins WHERE AdminID = 1")
    if rows and len(rows) > 0 and rows[0]:
        return rows[0]
    return {
        "TeamNum": "",
        "VersionNum": "",
        "ReleaseDate": "",
        "ProductName": "",
        "ProductDescription": ""
    }

def get_encryption_key():
    raw = os.environ.get('FIELD_ENCRYPTION_KEY') or hashlib.sha256(application.secret_key.encode('utf-8')).digest()
    if isinstance(raw, str):
        raw = raw.encode('utf-8')
    if len(raw) != 32:
        raw = hashlib.sha256(raw).digest()
    return base64.urlsafe_b64encode(raw)

def get_fernet():
    return Fernet(get_encryption_key())

def encrypt_value(value):
    if value in (None, ''):
        return value
    if isinstance(value, str) and value.startswith('enc::'):
        return value
    token = get_fernet().encrypt(str(value).encode('utf-8')).decode('utf-8')
    return f'enc::{token}'

def decrypt_value(value):
    if value in (None, ''):
        return value
    if not isinstance(value, str) or not value.startswith('enc::'):
        return value
    try:
        return get_fernet().decrypt(value[5:].encode('utf-8')).decode('utf-8')
    except InvalidToken:
        return value

def decrypt_fields(record, fields):
    if not record:
        return record
    for field in fields:
        if field in record:
            record[field] = decrypt_value(record.get(field))
    return record

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
	if "UserID" in session and session["role"] == "Sponsor":
		org = selectDb("""SELECT o.Name, o.OrganizationID
							FROM Users u 
							LEFT JOIN Sponsors s ON u.UserID = s.SponsorID 
							LEFT JOIN DriverOrganizations d ON u.UserID = d.DriverID
							LEFT JOIN Organizations o ON o.OrganizationID=COALESCE(s.OrganizationID, d.OrganizationID)
							WHERE u.UserID = %s""", (session['UserID'],))

		if org:
			organization = org[0]["Name"]
			if organization is not None:
				session['Organization'] = organization
				session['OrgID'] = org[0]["OrganizationID"]
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
		if "role" in session:
			return redirect(request.referrer)
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
    message, _ = get_login_lockout_message()
    if message:
        flash(message, "failedAttempts")
    return render_template("login.html")

@application.route("/login", methods=["POST"])
def loginUser():
    identifier = request.form.get("identifier", "").strip()
    password = request.form.get("password", "").strip()
    normalized_identifier = normalize_login_identifier(identifier)
    request_ip = get_request_ip()

    if not identifier or not password:
        flash("Please enter both your username/email and password.", "username")
        return redirect(url_for("login"))

    message, _ = get_login_lockout_message(identifier)
    if message:
        flash(message, "failedAttempts")
        return redirect(url_for("login"))

    exists = paramQueryDb(
        "SELECT UserID AS id, Username, Password_hash, UserType FROM Users WHERE Email=%s OR Username=%s",
        (identifier, identifier)
    )

    if not exists:
        ip_remaining = record_failed_login('ip', request_ip)
        acct_remaining = record_failed_login('account', normalized_identifier) if normalized_identifier else ip_remaining
        remaining = acct_remaining if normalized_identifier else ip_remaining

        if identifier:
            updateDb(
                """INSERT INTO Logins (LoginDate, LoginUser, LoginResult)
                VALUES (%s, %s, %s)""",
                (datetime.now(), identifier, False)
            )

        flash(f"Please enter the correct credentials. Attempts left {remaining} of {LOGIN_MAX_ATTEMPTS}", "username")
        return redirect(url_for("login"))

    if not check_password_hash(exists["Password_hash"], password):
        ip_remaining = record_failed_login('ip', request_ip)
        acct_remaining = record_failed_login('account', normalized_identifier) if normalized_identifier else ip_remaining
        remaining = acct_remaining if normalized_identifier else ip_remaining

        updateDb(
            """INSERT INTO Logins (LoginDate, LoginUser, LoginResult)
            VALUES (%s, %s, %s)""",
            (datetime.now(), identifier, False)
        )

        flash(f"Please enter the correct credentials. Attempts left {remaining} of {LOGIN_MAX_ATTEMPTS}", "password")
        return redirect(url_for("login"))

    remember = request.form.get("remember")
    session.permanent = bool(remember)

    clear_login_attempts('ip', request_ip)
    clear_login_attempts('account', normalized_identifier)

    session['UserID'] = exists['id']
    session['role'] = exists['UserType']
    session['Username'] = exists['Username']
    session['last_activity'] = datetime.utcnow().isoformat()
    session.pop('idle_warning_shown', None)

    updateDb(
        """INSERT INTO Logins (LoginDate, LoginUser, LoginResult)
        VALUES (%s, %s, %s) """,
        (datetime.now(), exists['Username'], True)
    )

    try:
        updateDb("UPDATE Users SET LastLogin=%s WHERE UserID=%s", (datetime.now(), exists['id']))
    except Exception as e:
        print('LastLogin update skipped:', e)

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
    last = session.get("last_reset_request")
    now = datetime.now().timestamp()

    if last and (now - last) < 10:
        flash("Please wait a moment before trying again.", "resetFail")
        return redirect(url_for("forgot_password"))
    session["last_reset_request"] = now

    if not email:
        flash("Please enter an email.", "resetFail")
        return redirect(url_for("forgot_password"))

    user = paramQueryDb("SELECT UserID FROM Users WHERE Email=%s", (email,))
    if user:
        log_password_event("reset_requested", actor_user_id=user["UserID"], target_user_id=user["UserID"])

        raw_token = secrets.token_urlsafe(32)
        token_hash = hash_reset_token(raw_token)
        expires = datetime.now() + timedelta(minutes=30)

        updateDb("""
            INSERT INTO PasswordResetTokens (UserID, TokenHash, ExpiresAt, UsedAt, CreatedAt, RequestIP)
            VALUES (%s, %s, %s, NULL, %s, %s)
        """, (user["UserID"], token_hash, expires, datetime.now(), get_request_ip()))

        log_password_event("reset_issued", actor_user_id=user["UserID"], target_user_id=user["UserID"])
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

DEFAULT_ROLE_PERMISSIONS = {
    'Admin': {
        'view_reports', 'export_reports', 'view_audit_logs', 'manage_role_permissions',
        'manage_security_settings', 'edit_about', 'manage_users'
    },
    'Sponsor': {'view_org_users', 'assume_driver_identity', 'adjust_driver_points'},
    'Driver': {'view_profile', 'checkout', 'view_orders'}
}

@application.before_request
def enforce_idle_timeout_and_security_headers():
    if request.endpoint == 'static':
        return None
    if 'UserID' in session:
        now = datetime.utcnow()
        last_activity_raw = session.get('last_activity')
        if last_activity_raw:
            try:
                last_activity = datetime.fromisoformat(last_activity_raw)
                idle_minutes = (now - last_activity).total_seconds() / 60.0
                if idle_minutes >= IDLE_TIMEOUT_MINUTES:
                    session.clear()
                    flash('Your session expired after inactivity. Please log in again.', 'failedAttempts')
                    return redirect(url_for('login'))
                if idle_minutes >= max(IDLE_TIMEOUT_MINUTES - IDLE_WARNING_MINUTES, 1) and not session.get('idle_warning_shown'):
                    flash(f'For security, inactive sessions are logged out after {IDLE_TIMEOUT_MINUTES} minutes.', 'registered')
                    session['idle_warning_shown'] = True
            except Exception:
                pass
        session['last_activity'] = now.isoformat()
    return None

@application.after_request
def apply_security_headers(response):
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    if os.environ.get('FLASK_ENV') == 'production':
        response.headers['Content-Security-Policy'] = "default-src 'self' https: data: 'unsafe-inline' 'unsafe-eval'"
    return response

@application.context_processor
def inject_permission_context():
    return {
        'current_permissions': get_role_permissions(session.get('role')),
        'idle_timeout_minutes': IDLE_TIMEOUT_MINUTES
    }

def init_security_tables():
    ddl_statements = [
        """CREATE TABLE IF NOT EXISTS LoginAttemptTracker (
            TrackerID INT AUTO_INCREMENT PRIMARY KEY,
            ScopeType VARCHAR(20) NOT NULL,
            ScopeValue VARCHAR(255) NOT NULL,
            FailedCount INT NOT NULL DEFAULT 0,
            LockedUntil DATETIME NULL,
            LastFailedAt DATETIME NULL,
            CreatedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UpdatedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            UNIQUE KEY uq_login_attempt_scope (ScopeType, ScopeValue)
        )""",
        """CREATE TABLE IF NOT EXISTS RolePermissions (
            PermissionID INT AUTO_INCREMENT PRIMARY KEY,
            RoleName VARCHAR(32) NOT NULL,
            PermissionName VARCHAR(100) NOT NULL,
            IsAllowed TINYINT(1) NOT NULL DEFAULT 1,
            CreatedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UpdatedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            UNIQUE KEY uq_role_permission (RoleName, PermissionName)
        )"""
    ]
    for ddl in ddl_statements:
        try:
            updateDb(ddl)
        except Exception as e:
            print('init_security_tables skipped:', e)

def seed_default_role_permissions():
    for role, permissions in DEFAULT_ROLE_PERMISSIONS.items():
        for permission in permissions:
            try:
                updateDb("""
                    INSERT INTO RolePermissions (RoleName, PermissionName, IsAllowed)
                    VALUES (%s, %s, 1)
                    ON DUPLICATE KEY UPDATE UpdatedAt = CURRENT_TIMESTAMP
                """, (role, permission))
            except Exception as e:
                print('seed_default_role_permissions skipped:', e)

def get_role_permissions(role_name):
    if not role_name:
        return set()
    rows = selectDb("SELECT PermissionName FROM RolePermissions WHERE RoleName=%s AND IsAllowed=1", (role_name,))
    if rows:
        return {row['PermissionName'] for row in rows}
    return set(DEFAULT_ROLE_PERMISSIONS.get(role_name, set()))

def has_permission(permission_name):
    return permission_name in get_role_permissions(session.get('role'))

def permission_required(permission_name):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            guard = require_login()
            if guard:
                return guard
            if not has_permission(permission_name):
                flash('You do not have permission to access that page.', 'auth')
                return redirect(url_for('home'))
            return func(*args, **kwargs)
        return wrapper
    return decorator

def normalize_login_identifier(identifier):
    return (identifier or '').strip().lower()

def get_active_lockout(scope_type, scope_value):
    if not scope_value:
        return None
    row = paramQueryDb("""
        SELECT FailedCount, LockedUntil
        FROM LoginAttemptTracker
        WHERE ScopeType=%s AND ScopeValue=%s
    """, (scope_type, scope_value))
    if row and row.get('LockedUntil') and datetime.utcnow() < row['LockedUntil']:
        return row
    return None

def clear_login_attempts(scope_type, scope_value):
    if not scope_value:
        return
    updateDb("DELETE FROM LoginAttemptTracker WHERE ScopeType=%s AND ScopeValue=%s", (scope_type, scope_value))

def record_failed_login(scope_type, scope_value):
    if not scope_value:
        return LOGIN_MAX_ATTEMPTS - 1

    existing = paramQueryDb("""
        SELECT FailedCount, LockedUntil
        FROM LoginAttemptTracker
        WHERE ScopeType=%s AND ScopeValue=%s
    """, (scope_type, scope_value))

    current_failed = int(existing.get("FailedCount") or 0) if existing else 0
    failed_count = current_failed + 1
    locked_until = datetime.utcnow() + timedelta(minutes=LOGIN_LOCKOUT_MINUTES) if failed_count >= LOGIN_MAX_ATTEMPTS else None

    updateDb("""
        INSERT INTO LoginAttemptTracker (ScopeType, ScopeValue, FailedCount, LockedUntil, LastFailedAt)
        VALUES (%s, %s, %s, %s, %s)
        ON DUPLICATE KEY UPDATE
            FailedCount = %s,
            LockedUntil = %s,
            LastFailedAt = %s
    """, (
        scope_type, scope_value, failed_count, locked_until, datetime.utcnow(),
        failed_count, locked_until, datetime.utcnow()
    ))

    return max(LOGIN_MAX_ATTEMPTS - failed_count, 0)
def get_login_lockout_message(identifier=None):
    ip = get_request_ip()
    normalized_identifier = normalize_login_identifier(identifier)
    for scope_type, scope_value, scope_label in (('ip', ip, 'your IP address'), ('account', normalized_identifier, 'this account')):
        active = get_active_lockout(scope_type, scope_value)
        if active:
            remaining = active['LockedUntil'] - datetime.utcnow()
            minutes_remaining = max(int(remaining.total_seconds() // 60) + 1, 1)
            return f'Too many failed attempts for {scope_label}. Try again in {minutes_remaining} minute(s).', minutes_remaining
    return None, 0

# Define security tables and seed default permissions on startup
init_security_tables()
seed_default_role_permissions()

def stop_admin_view_as_session():
	if "admin_real_UserID" not in session:
		return

	session["UserID"] = session["admin_real_UserID"]
	session["role"] = session["admin_real_role"]
	session["Organization"] = session.get("admin_real_Organization")
	session["OrgID"] = session.get("admin_real_OrgID", 0)

	session.pop("admin_real_UserID", None)
	session.pop("admin_real_role", None)
	session.pop("admin_real_Organization", None)
	session.pop("admin_real_OrgID", None)
	session.pop("impersonating_target_UserID", None)

@application.route("/logout")
def logout():
	session.pop("UserID", None)
	session.pop("role", None)
	session.pop("Username", None)
	session.pop("Organization", None)
	session.pop("OrgID", None)
	session.pop("admin_real_UserID", None)
	session.pop("admin_real_role", None)
	session.pop("admin_real_Organization", None)
	session.pop("admin_real_OrgID", None)
	session.pop("impersonating_target_UserID", None)
	session.pop("attempts", None)
	session.pop("lockoutTime", None)

	session.pop("impersonating", None)
	session.pop("original_UserID", None)
	session.pop("original_role", None)
	session.pop("original_Organization", None)
	session.pop("original_OrgID", None)

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

@application.route("/admin/users/<int:UserID>/view-as", methods=["POST"])
def adminViewAsUser(UserID):
	guard = require_admin()
	if guard:
		return guard

	target = paramQueryDb("""
		SELECT u.UserID, u.UserType,
			   COALESCE(s.OrganizationID, d.OrganizationID) AS OrganizationID,
			   o.Name AS OrganizationName
		FROM Users u
		LEFT JOIN Sponsors s ON u.UserID = s.SponsorID
		LEFT JOIN DriverOrganizations d ON u.UserID = d.DriverID
		LEFT JOIN Organizations o ON o.OrganizationID = COALESCE(s.OrganizationID, d.OrganizationID)
		WHERE u.UserID = %s
	""", (UserID,))

	if not target:
		flash("Target user not found.", "validation")
		return redirect(url_for("adminUserList"))

	if target["UserType"] not in ("Driver", "Sponsor"):
		flash("Admin can only view as a Driver or Sponsor.", "validation")
		return redirect(url_for("adminUserList"))

	# save the real admin identity only once
	if "admin_real_UserID" not in session:
		session["admin_real_UserID"] = session["UserID"]
		session["admin_real_role"] = session["role"]
		session["admin_real_Organization"] = session.get("Organization")
		session["admin_real_OrgID"] = session.get("OrgID", 0)

	# switch session to target user
	session["UserID"] = target["UserID"]
	session["role"] = target["UserType"]
	session["Organization"] = target["OrganizationName"]
	session["OrgID"] = target["OrganizationID"] if target["OrganizationID"] is not None else 0
	session["impersonating_target_UserID"] = target["UserID"]

	flash(f"Now viewing as {target['UserType']} (UserID {target['UserID']}).", "success")

	if target["OrganizationName"]:
		return redirect(url_for("organization"))
	return redirect(url_for("home"))

@application.route("/admin/stop-view-as", methods=["POST"])
def adminStopViewAs():
	if "admin_real_UserID" not in session:
		flash("You are not currently viewing as another user.", "validation")
		return redirect(url_for("home"))

	stop_admin_view_as_session()
	flash("Returned to admin view.", "success")
	return redirect(url_for("adminUserList"))

# ===== admin enroll driver into a selected organization =====
@application.route("/organizations/<int:OrganizationID>/enroll-driver")
def adminEnrollDriverPage(OrganizationID):
	guard = require_admin()
	if guard:
		return guard

	org = paramQueryDb("""
		SELECT OrganizationID, Name
		FROM Organizations
		WHERE OrganizationID = %s
	""", (OrganizationID,))

	if not org:
		flash("Organization not found.", "notfound")
		return redirect(url_for("organizations"))

	q = request.args.get("q", "").strip()
	like = f"%{q}%"

	page = request.args.get("page", 1, type=int)
	rowsPerPage = request.args.get("pageCount", 10, type=int)
	offset = (page - 1) * rowsPerPage

	if q:
		rowTotal = selectDb("""
			SELECT COUNT(*) AS totalRows
			FROM Users u
			JOIN DriverOrganizations d ON u.UserID = d.DriverID
			WHERE u.UserType = "Driver"
			AND (d.OrganizationID IS NULL OR d.OrganizationID = 0)
			AND (u.Name LIKE %s OR u.Email LIKE %s OR u.Username LIKE %s)
		""", (like, like, like))

		drivers = selectDb("""
			SELECT u.UserID, u.Name, u.Email, u.Username
			FROM Users u
			JOIN DriverOrganizations d ON u.UserID = d.DriverID
			WHERE u.UserType = "Driver"
			AND (d.OrganizationID IS NULL OR d.OrganizationID = 0)
			AND (u.Name LIKE %s OR u.Email LIKE %s OR u.Username LIKE %s)
			ORDER BY u.Name
			LIMIT %s OFFSET %s
		""", (like, like, like, rowsPerPage, offset))
	else:
		rowTotal = selectDb("""
			SELECT COUNT(*) AS totalRows
			FROM Users u
			JOIN DriverOrganizations d ON u.UserID = d.DriverID
			WHERE u.UserType = "Driver"
			AND (d.OrganizationID IS NULL OR d.OrganizationID = 0)
		""", ())

		drivers = selectDb("""
			SELECT u.UserID, u.Name, u.Email, u.Username
			FROM Users u
			JOIN DriverOrganizations d ON u.UserID = d.DriverID
			WHERE u.UserType = "Driver"
			AND (d.OrganizationID IS NULL OR d.OrganizationID = 0)
			ORDER BY u.Name
			LIMIT %s OFFSET %s
		""", (rowsPerPage, offset))

	totalRows = rowTotal[0]["totalRows"] if rowTotal else 0
	numPages = max(1, math.ceil(totalRows / rowsPerPage))

	return render_template(
		"userList.html",
		layout="activenav.html",
		users=drivers,
		q=q,
		accountType="admin",
		use="enroll_driver",
		page=page,
		pageNum=range(1, numPages + 1),
		pageRows=rowsPerPage,
		targetOrg=org
	)

def get_org_by_name(org_name):
    return paramQueryDb("""
        SELECT OrganizationID, Name
        FROM Organizations
        WHERE Name = %s
    """, (org_name,))

def get_driver_by_identifier(identifier):
    return paramQueryDb("""
        SELECT u.UserID, u.Name, u.Email, u.Username, d.OrganizationID
        FROM Users u
        JOIN DriverOrganizations d ON d.DriverID = u.UserID
        WHERE u.UserType = 'Driver'
          AND (u.Username = %s OR u.Email = %s OR u.Name = %s)
        LIMIT 1
    """, (identifier, identifier, identifier))

@application.route("/organizations/enroll-driver", methods=["GET", "POST"])
@permission_required("manage_users")
def enroll_driver_without_numeric_ids():
    if request.method == "GET":
        organizations = selectDb("""
            SELECT OrganizationID, Name
            FROM Organizations
            ORDER BY Name
        """, ()) or []
        return render_template(
            "enroll_driver_lookup.html",
            layout="activenav.html",
            organizations=organizations
        )

    org_name = request.form.get("organizationName", "").strip()
    driver_identifier = request.form.get("driverIdentifier", "").strip()

    org = get_org_by_name(org_name)
    if not org:
        flash("Organization not found.", "notfound")
        return redirect(url_for("enroll_driver_without_numeric_ids"))

    driver = get_driver_by_identifier(driver_identifier)
    if not driver:
        flash("Driver not found.", "notfound")
        return redirect(url_for("enroll_driver_without_numeric_ids"))

    updateDb("""
        UPDATE DriverOrganizations
        SET OrganizationID = %s
        WHERE DriverID = %s
    """, (org["OrganizationID"], driver["UserID"]))

    flash(f"Enrolled {driver['Name']} into {org['Name']}.", "success")
    return redirect(url_for("enroll_driver_without_numeric_ids"))

@application.route("/organizations/<int:OrganizationID>/enroll-driver/<int:UserID>", methods=["POST"])
def adminEnrollDriverPost(OrganizationID, UserID):
	guard = require_admin()
	if guard:
		return guard

	org = paramQueryDb("""
		SELECT OrganizationID, Name
		FROM Organizations
		WHERE OrganizationID = %s
	""", (OrganizationID,))

	if not org:
		flash("Organization not found.", "notfound")
		return redirect(url_for("organizations"))

	driver = paramQueryDb("""
		SELECT u.UserID, u.Name, u.Username, d.OrganizationID
		FROM Users u
		JOIN DriverOrganizations d ON u.UserID = d.DriverID
		WHERE u.UserID = %s AND u.UserType = "Driver"
	""", (UserID,))

	if not driver:
		flash("Driver not found.", "notfound")
		return redirect(url_for("adminEnrollDriverPage", OrganizationID=OrganizationID))

	if driver["OrganizationID"] not in (None, 0):
		flash("This driver is already enrolled in an organization.", "validation")
		return redirect(url_for("adminEnrollDriverPage", OrganizationID=OrganizationID))

	# enroll the driver directly
	updateDb("""
		UPDATE DriverOrganizations
		SET OrganizationID = %s
		WHERE DriverID = %s
	""", (OrganizationID, UserID))

	# clean up any pending applications for this driver
	updateDb("""
		DELETE FROM OrganizationApplications
		WHERE DriverUName = %s AND ApplicationStatus = "Pending"
	""", (driver["Username"],))

	flash(f'{driver["Name"]} was enrolled into {org["Name"]}.', "success")
	return redirect(url_for("adminEnrollDriverPage", OrganizationID=OrganizationID))

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
	allowed_types = {"passwords", "points", "applications", "logins"}
	if ReportType not in allowed_types:
		flash("Unknown report requested.", "validation")
		return redirect(url_for("home"))

	org_id = get_user_org_id()
	org_name = get_effective_org_name()

	start = request.args.get("start", "").strip()
	end = request.args.get("end", "").strip()
	driver_filter = request.args.get("driver", "").strip()
	csv_export = request.args.get("format") == "csv"

	page = request.args.get("page", 1, type=int)
	rowsPerPage = request.args.get("pageCount", 10, type=int)
	offset = (page - 1) * rowsPerPage

	where_clauses = []
	params = []

	date_field = {
		"passwords": "pa.DateAdjusted",
		"points": "pa.DateAdjusted",
		"applications": "a.DateApplied",
		"logins": "l.LoginDate"
	}[ReportType]

	if ReportType in ["points", "applications"] and org_name:
		if not org_id:
			flash("Organization not found.", "validation")
			return redirect(url_for("home"))

		if ReportType == "points":
			where_clauses.append("pa.OrganizationID=%s")
		else:
			where_clauses.append("a.OrganizationID=%s")
		params.append(org_id)

	elif ReportType == "passwords" and org_name:
		where_clauses.append("COALESCE(ts_org.Name, td_org.Name) = %s")
		params.append(org_name)

	elif ReportType == "logins" and org_name:
		where_clauses.append("COALESCE(ls_org.Name, ld_org.Name) = %s")
		params.append(org_name)

	if start:
		where_clauses.append(f"{date_field} >= %s")
		params.append(start + " 00:00:00")

	if end:
		where_clauses.append(f"{date_field} <= %s")
		params.append(end + " 23:59:59")

	if ReportType == "points" and driver_filter:
		like = f"%{driver_filter}%"
		where_clauses.append("(u.Name LIKE %s OR u.Email LIKE %s OR u.Username LIKE %s)")
		params.extend([like, like, like])

	where = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""

	if ReportType == "passwords":
		count_query = f"""
			SELECT COUNT(*) AS totalRows
			FROM PasswordAdjustments pa
			JOIN Users u ON u.Username = pa.AdjustedUName
			LEFT JOIN Sponsors ts ON u.UserID = ts.SponsorID
			LEFT JOIN DriverOrganizations td ON u.UserID = td.DriverID
			LEFT JOIN Organizations ts_org ON ts.OrganizationID = ts_org.OrganizationID
			LEFT JOIN Organizations td_org ON td.OrganizationID = td_org.OrganizationID
			LEFT JOIN Users x ON x.Username = pa.AdjustedByUName
			{where}
		"""
		data_query = f"""
			SELECT
				pa.DateAdjusted,
				pa.TypeOfChange,
				COALESCE(x.Name, pa.AdjustedByUName) AS Actor,
				u.Name AS Target
			FROM PasswordAdjustments pa
			JOIN Users u ON u.Username = pa.AdjustedUName
			LEFT JOIN Sponsors ts ON u.UserID = ts.SponsorID
			LEFT JOIN DriverOrganizations td ON u.UserID = td.DriverID
			LEFT JOIN Organizations ts_org ON ts.OrganizationID = ts_org.OrganizationID
			LEFT JOIN Organizations td_org ON td.OrganizationID = td_org.OrganizationID
			LEFT JOIN Users x ON x.Username = pa.AdjustedByUName
			{where}
			ORDER BY pa.DateAdjusted DESC
		"""
		csv_headers = ["DateAdjusted", "Actor", "Target", "TypeOfChange"]

	elif ReportType == "points":
		count_query = f"""
            SELECT COUNT(*) AS totalRows
            FROM PointAdjustments pa
            JOIN Users u ON u.Username = pa.DriverUName
            {where}
        """
		data_query = f"""
            SELECT
                pa.DateAdjusted,
                u.Name AS DriverName,
                pa.DriverUName,
                pa.AdjustedByUName,
                CONCAT(
                    CASE WHEN pa.AdjustmentType='Deduct' THEN '-' ELSE '+' END,
                    pa.AdjustmentPoints
                ) AS DeltaPoints,
                pa.AdjustmentType,
                pa.AdjustmentPoints,
                pa.AdjustmentReason
            FROM PointAdjustments pa
            JOIN Users u ON u.Username = pa.DriverUName
            {where}
            ORDER BY pa.DateAdjusted DESC
        """
		csv_headers = ["DateAdjusted", "DriverName", "DriverUName", "AdjustedByUName", "DeltaPoints", "AdjustmentReason"]

	elif ReportType == "applications":
		count_query = f"""
            SELECT COUNT(*) AS totalRows
            FROM OrganizationApplications a
            JOIN Organizations o ON a.OrganizationID = o.OrganizationID
            {where}
        """
		data_query = f"""
			SELECT
				a.DateApplied,
				o.Name,
				a.DriverUName,
				a.ReviewedByUName,
				a.ApplicationStatus,
				a.ReviewReason
			FROM OrganizationApplications a
			JOIN Organizations o ON a.OrganizationID = o.OrganizationID
			{where}
			ORDER BY a.ApplicationStatus Desc, a.DateApplied DESC
		"""
		csv_headers = ["DateApplied", "Name", "DriverUName", "ReviewedByUName", "ApplicationStatus", "ReviewReason"]

	else:
		count_query = f"""
			SELECT COUNT(*) AS totalRows
			FROM Logins l
			LEFT JOIN Users lu ON (lu.Email = l.LoginUser OR lu.Username = l.LoginUser)
			LEFT JOIN Sponsors ls ON lu.UserID = ls.SponsorID
			LEFT JOIN DriverOrganizations ld ON lu.UserID = ld.DriverID
			LEFT JOIN Organizations ls_org ON ls.OrganizationID = ls_org.OrganizationID
			LEFT JOIN Organizations ld_org ON ld.OrganizationID = ld_org.OrganizationID
			{where}
		"""
		data_query = f"""
			SELECT
				l.LoginDate,
				l.LoginUser,
				CASE
					WHEN l.LoginResult = 1 THEN 'Successful Login'
					WHEN l.LoginResult = 0 THEN 'Failed Login'
				END AS LoginStatus
			FROM Logins l
			LEFT JOIN Users lu ON (lu.Email = l.LoginUser OR lu.Username = l.LoginUser)
			LEFT JOIN Sponsors ls ON lu.UserID = ls.SponsorID
			LEFT JOIN DriverOrganizations ld ON lu.UserID = ld.DriverID
			LEFT JOIN Organizations ls_org ON ls.OrganizationID = ls_org.OrganizationID
			LEFT JOIN Organizations ld_org ON ld.OrganizationID = ld_org.OrganizationID
			{where}
			ORDER BY l.LoginDate DESC
		"""
		csv_headers = ["LoginDate", "LoginUser", "LoginStatus"]

	rowTotal = selectDb(count_query, tuple(params)) or [{"totalRows": 0}]

	if csv_export:
		rows = selectDb(data_query, tuple(params)) or []
		return build_csv_response(f"{ReportType}_report.csv", csv_headers, rows)

	rows = selectDb(data_query + " LIMIT %s OFFSET %s", tuple(list(params) + [rowsPerPage, offset])) or []

	total_rows = rowTotal[0]["totalRows"] if rowTotal else 0
	numPages = max(1, math.ceil(total_rows / rowsPerPage)) if rowsPerPage else 1

	if session.get("role") == "Admin" and session.get("Organization") == None:
		nav = "activenav.html"
	elif session.get("role") == "Admin" and session.get("Organization") != None:
		nav = "orgnav.html"
	else:
		nav = "orgnav.html" if session.get("Organization") else "activenav.html"

	return render_template(
        "logReports.html",
        layout=nav,
        rows=rows,
        start=start,
        end=end,
        driverFilter=driver_filter,
        ReportType=ReportType,
        page=page,
        pageNum=range(1, numPages + 1),
        pageRows=rowsPerPage
    )

@application.route("/reports/sales-by-driver")
@permission_required("view_reports")
def salesByDriverReport():
	start = request.args.get("start", "").strip()
	end = request.args.get("end", "").strip()
	driverFilter = request.args.get("driver", "").strip()
	organizationFilter = request.args.get("organization", "").strip()
	page = request.args.get("page", 1, type=int)
	rowsPerPage = request.args.get("pageCount", 10, type=int)
	offset = (page - 1) * rowsPerPage
	export_format = request.args.get("format", "").lower()

	count_query = """
		SELECT
			COUNT(DISTINCT o.userID) AS totalRows
		FROM OrderItems oi
		JOIN Orders o ON o.orderID = oi.orderID
		JOIN Users u ON u.UserID = o.userID
		JOIN DriverOrganizations d ON u.userID = d.DriverID
		JOIN Organizations org ON d.OrganizationID = org.OrganizationID
	"""
	base_query = """
        SELECT
            o.userID,
            COUNT(DISTINCT o.orderID) AS orderCount,
            SUM(oi.amount) AS quantityBought,
            SUM(oi.totalPrice) AS grossSales
        FROM OrderItems oi
        JOIN Orders o ON o.orderID = oi.orderID
		JOIN Users u ON u.UserID = o.userID
		JOIN DriverOrganizations d ON u.userID = d.DriverID
		JOIN Organizations org ON d.OrganizationID = org.OrganizationID
    """
	params = []
	where_clauses = []

	if session.get("Organization") != None:
		where_clauses.append("o.orgID = %s")
		params.append(session["OrgID"])

	if start:
		where_clauses.append("o.orderTime >= %s")
		params.append(start + " 00:00:00")

	if end:
		where_clauses.append("o.orderTime <= %s")
		params.append(end + " 23:59:59")

	if driverFilter:
		driver = f"%{driverFilter}%"
		where_clauses.append("""
			(
				u.Email LIKE %s OR
				u.Username LIKE %s OR
				u.Name LIKE %s
			)
		""")
		params.extend([driver, driver, driver])

	if organizationFilter:
		organization = f"%{organizationFilter}%"
		where_clauses.append("org.Name LIKE %s")
		params.append(organization)

	if where_clauses:
		count_query += " WHERE " + " AND ".join(where_clauses)
		base_query += " WHERE " + " AND ".join(where_clauses)

	base_query += """
		GROUP BY o.userID
		ORDER BY grossSales DESC, quantityBought DESC
		LIMIT %s OFFSET %s
		"""

	rowTotal = selectDb(count_query, tuple(params)) or [{"totalRows": 0}]
	rows = selectDb(base_query, tuple(list(params) + [rowsPerPage, offset])) or []

	total_rows = rowTotal[0]["totalRows"] if rowTotal else 0
	numPages = max(1, math.ceil(total_rows / rowsPerPage)) if rowsPerPage else 1

	try:
		driverData = getDriverData() or {}
	except Exception:
		driverData = {}

	enriched_rows = []
	for row in rows:
		userID = row.get("userID")

		enriched_rows.append({
			"driverID": userID,
			"driverName": next((driver["Username"] for driver in driverData if driver["UserID"] == userID), "None"),
			"orderCount": row.get("orderCount") or 0,
			"quantityBought": row.get("quantityBought") or 0,
			"grossSales": float(row.get("grossSales") or 0)
		})

	rows = enriched_rows

	summary = {
		"userCount": len(rows),
		"quantityBought": sum(int(r.get("quantityBought") or 0) for r in rows),
		"grossSales": sum(float(r.get("grossSales") or 0) for r in rows)
	}

	if export_format == "csv":
		return build_csv_response(
			"sales_by_product_report.csv",
			["driverID", "driverName", "orderCount", "quantityBought", "grossSales"],
			rows
		)

	return render_template(
		"salesByDriverReport.html",
		layout="nav.html" if not session.get("UserID") else ("orgnav.html" if session.get("Organization") != None else "activenav.html"),
		rows=rows,
		summary=summary,
		driverFilter=driverFilter,
		organizationFilter=organizationFilter,
		page=page,
        pageNum=range(1, numPages + 1),
        pageRows=rowsPerPage
	)

@application.route("/reports/sales-by-organization")
@permission_required("view_reports")
def salesByOrganizationReport():
	start = request.args.get("start", "").strip()
	end = request.args.get("end", "").strip()
	organizationFilter = request.args.get("organization", "").strip()
	page = request.args.get("page", 1, type=int)
	rowsPerPage = request.args.get("pageCount", 10, type=int)
	offset = (page - 1) * rowsPerPage
	export_format = request.args.get("format", "").lower()
	
	count_query = """
		SELECT
            COUNT(DISTINCT o.orgID) AS totalRows
        FROM OrderItems oi
        JOIN Orders o ON o.orderID = oi.orderID
		JOIN Organizations org ON o.orgID = org.OrganizationID
    """
	base_query = """
        SELECT
            o.orgID,
            COUNT(DISTINCT o.orderID) AS orderCount,
            SUM(oi.amount) AS quantityBought,
            SUM(oi.totalPrice) AS grossSales
        FROM OrderItems oi
        JOIN Orders o ON o.orderID = oi.orderID
		JOIN Organizations org ON o.orgID = org.OrganizationID
    """
	params = []
	where_clauses = []

	if start:
		where_clauses.append("orderTime >= %s")
		params.append(start + " 00:00:00")

	if end:
		where_clauses.append("orderTime <= %s")
		params.append(end + " 23:59:59")

	if organizationFilter:
		organization = f"%{organizationFilter}%"
		where_clauses.append("org.Name LIKE %s")
		params.append(organization)

	if where_clauses:
		base_query += " WHERE " + " AND ".join(where_clauses)

	base_query += """
		GROUP BY o.orgID
		ORDER BY grossSales DESC, quantityBought DESC
		LIMIT %s OFFSET %s
		"""

	rowTotal = selectDb(count_query, tuple(params)) or [{"totalRows": 0}]
	rows = selectDb(base_query, tuple(list(params) + [rowsPerPage, offset])) or []

	total_rows = rowTotal[0]["totalRows"] if rowTotal else 0
	numPages = max(1, math.ceil(total_rows / rowsPerPage)) if rowsPerPage else 1

	try:
		orgData = getOrgData() or {}
	except Exception:
		orgData = {}

	enriched_rows = []
	for row in rows:
		orgID = row.get("orgID")

		enriched_rows.append({
			"orgID": orgID,
			"organizationName": next((org["Name"] for org in orgData if org["OrganizationID"] == orgID), "None"),
			"orderCount": row.get("orderCount") or 0,
			"quantityBought": row.get("quantityBought") or 0,
			"grossSales": float(row.get("grossSales") or 0)
		})

	rows = enriched_rows

	summary = {
		"organizationCount": len(rows),
		"quantityBought": sum(int(r.get("quantityBought") or 0) for r in rows),
		"grossSales": sum(float(r.get("grossSales") or 0) for r in rows)
	}

	if export_format == "csv":
		return build_csv_response(
			"sales_by_product_report.csv",
			["orgID", "organizationName", "orderCount", "quantityBought", "grossSales"],
			rows
		)

	return render_template(
		"salesByOrgReport.html",
		layout="nav.html" if not session.get("UserID") else ("activenav.html"),
		rows=rows,
		summary=summary,
		organizationFilter=organizationFilter,
		page=page,
        pageNum=range(1, numPages + 1),
        pageRows=rowsPerPage
	)

@application.route("/reports/sales-by-product")
@permission_required("view_reports")
def sales_by_product_report():
	start = request.args.get("start", "").strip()
	end = request.args.get("end", "").strip()
	page = request.args.get("page", 1, type=int)
	rowsPerPage = request.args.get("pageCount", 10, type=int)
	offset = (page - 1) * rowsPerPage
	org_id = request.args.get("orgID", type=int)
	export_format = request.args.get("format", "").lower()

	rows, numPages = get_sales_by_product_rows(org_id=org_id, start=start, end=end, rowsPerPage=rowsPerPage, offset=offset)

	summary = {
		"productCount": len(rows),
		"quantitySold": sum(int(r.get("quantitySold") or 0) for r in rows),
		"grossSales": sum(float(r.get("grossSales") or 0) for r in rows)
	}

	if export_format == "csv":
		return build_csv_response(
			"sales_by_product_report.csv",
			["productID", "productName", "category", "brand", "orderCount", "quantitySold", "grossSales"],
			rows
		)

	return render_template(
		"sales_by_product_report.html",
		layout="nav.html" if not session.get("UserID") else ("orgnav.html" if session.get("Organization") else "activenav.html"),
		rows=rows,
		summary=summary,
		page=page,
        pageNum=range(1, numPages + 1),
        pageRows=rowsPerPage
	)

@application.route("/reports/refunds-impact")
@permission_required("view_reports")
def refunds_impact_report():
    org_id = request.args.get("orgID", type=int)
    export_format = request.args.get("format", "").lower()

    summary, rows = get_refund_cancellation_impact_rows(org_id=org_id)

    if export_format == "csv":
        return build_csv_response(
            "refunds_impact_report.csv",
            ["orderID", "orgID", "pointTotal", "status", "orderTime"],
            rows
        )

    return render_template(
        "refunds_impact_report.html",
        layout="nav.html" if not session.get("UserID") else ("orgnav.html" if session.get("Organization") else "activenav.html"),
        summary=summary,
        rows=rows
    )

@application.route("/admin/orders/<int:order_id>/status", methods=["POST"])
@permission_required("manage_users")
def admin_update_order_status(order_id):
    status_name = request.form.get("statusName", "").strip()
    notes = request.form.get("notes", "").strip()

    allowed_statuses = {"Refunded", "Cancelled", "Completed"}
    if status_name not in allowed_statuses:
        flash("Invalid order status.", "validation")
        return redirect(url_for("refunds_impact_report"))

    existing_order = paramQueryDb("SELECT orderID FROM Orders WHERE orderID = %s", (order_id,))
    if not existing_order:
        flash("Order not found.", "notfound")
        return redirect(url_for("refunds_impact_report"))

    updateDb("""
        INSERT INTO OrderStatusAudit (OrderID, StatusName, Notes)
        VALUES (%s, %s, %s)
    """, (order_id, status_name, notes))

    flash(f"Order {order_id} marked as {status_name}.", "success")
    return redirect(url_for("refunds_impact_report"))

@application.route("/reports/invoices")
@permission_required("view_reports")
def invoice_report():
	start = request.args.get("start", "").strip()
	end = request.args.get("end", "").strip()
	page = request.args.get("page", 1, type=int)
	rowsPerPage = request.args.get("pageCount", 10, type=int)
	offset = (page - 1) * rowsPerPage
	fee_rate = request.args.get("feeRate", default=0.01, type=float)
	export_format = request.args.get("format", "").lower()

	rows, numPages = get_invoice_rows(fee_rate=fee_rate, start=start, end=end, rowsPerPage=rowsPerPage, offset=offset)

	if export_format == "csv":
		return build_csv_response(
			"invoice_report.csv",
			["orgID", "organizationName", "orderCount", "salesTotal", "feeRate", "feeAmount", "invoiceTotal", "feeExplanation"],
			rows
		)

	return render_template(
		"invoice_report.html",
		layout="nav.html" if not session.get("UserID") else ("orgnav.html" if session.get("Organization") else "activenav.html"),
		rows=rows,
		feeRate=fee_rate,
		page=page,
        pageNum=range(1, numPages + 1),
        pageRows=rowsPerPage
	)

@application.route("/reports/invoices/resend", methods=["POST"])
@permission_required("view_reports")
def resend_invoice_email():
    org_id = request.form.get("orgID", type=int)
    invoice_month = request.form.get("invoiceMonth", "").strip() or datetime.now().strftime("%Y-%m")

    org = paramQueryDb("""
        SELECT OrganizationID, Name
        FROM Organizations
        WHERE OrganizationID = %s
    """, (org_id,))

    if not org:
        flash("Organization not found.", "notfound")
        return redirect(url_for("invoice_report"))

    sponsor = paramQueryDb("""
        SELECT u.Email
        FROM Sponsors s
        JOIN Users u ON u.UserID = s.SponsorID
        WHERE s.OrganizationID = %s
        ORDER BY u.UserID
        LIMIT 1
    """, (org_id,))

    recipient_email = sponsor.get("Email") if sponsor else None

    updateDb("""
        INSERT INTO InvoiceEmailLog (OrgID, InvoiceMonth, RecipientEmail, ActionTaken, TriggeredByUserID, Notes)
        VALUES (%s, %s, %s, %s, %s, %s)
    """, (
        org_id,
        invoice_month,
        recipient_email,
        "resent",
        session.get("UserID"),
        f"Invoice resend triggered for {org.get('Name')}"
    ))

    try:
        updateDb("""
            INSERT INTO Logins (LoginDate, LoginUser, LoginResult)
            VALUES (%s, %s, %s)
        """, (datetime.now(), f"invoice-resend-org-{org_id}", True))
    except Exception as e:
        print("invoice resend audit log skipped:", e)

    flash(f"Invoice resend recorded for {org.get('Name')}.", "success")
    return redirect(url_for("invoice_report"))

@application.route("/admin/audit-logs")
@permission_required("view_audit_logs")
def audit_logs():
    keyword = request.args.get("q", "").strip()
    sponsor_filter = request.args.get("sponsor", "").strip()
    start_date = request.args.get("start", "").strip()
    end_date = request.args.get("end", "").strip()
    category_filter = request.args.get("category", "").strip()
    export_format = request.args.get("format", "").lower()

    page = request.args.get("page", 1, type=int)
    rowsPerPage = request.args.get("pageCount", 20, type=int)

    if rowsPerPage not in [20, 50, 100]:
        rowsPerPage = 20

    offset = (page - 1) * rowsPerPage

    base_query = """
		SELECT *
		FROM (
			SELECT
				pa.DateAdjusted AS EventDate,
				'PasswordAdjustments' AS SourceTable,
				pa.TypeOfChange AS EventType,
				COALESCE(actor.Name, pa.AdjustedByUName) AS Actor,
				actor.Email AS ActorEmail,
				COALESCE(target.Name, pa.AdjustedUName) AS Target,
				target.Email AS TargetEmail,
				CONCAT('Password change event for ', pa.AdjustedUName) AS Details,
				COALESCE(s_actor.Name, s_target.Name, '') AS SponsorName,
				COALESCE(s_actor.Email, s_target.Email, '') AS SponsorEmail,
				COALESCE(s_actor.Username, s_target.Username, '') AS SponsorUsername
			FROM PasswordAdjustments pa
			LEFT JOIN Users actor ON actor.Username = pa.AdjustedByUName
			LEFT JOIN Users target ON target.Username = pa.AdjustedUName
			LEFT JOIN Users s_actor ON s_actor.UserType = 'Sponsor' AND s_actor.Username = pa.AdjustedByUName
			LEFT JOIN Users s_target ON s_target.UserType = 'Sponsor' AND s_target.Username = pa.AdjustedUName

			UNION ALL

			SELECT
				l.LoginDate AS EventDate,
				'Logins' AS SourceTable,
				CASE
					WHEN l.LoginResult = 1 THEN 'Successful Login'
					ELSE 'Failed Login'
				END AS EventType,
				COALESCE(u.Name, l.LoginUser) AS Actor,
				u.Email AS ActorEmail,
				'' AS Target,
				'' AS TargetEmail,
				CONCAT('Login user: ', l.LoginUser) AS Details,
				COALESCE(s_u.Name, '') AS SponsorName,
				COALESCE(s_u.Email, '') AS SponsorEmail,
				COALESCE(s_u.Username, '') AS SponsorUsername
			FROM Logins l
			LEFT JOIN Users u ON (u.Email = l.LoginUser OR u.Username = l.LoginUser)
			LEFT JOIN Users s_u ON s_u.UserType = 'Sponsor' AND s_u.UserID = u.UserID

			UNION ALL

			SELECT
				p.DateAdjusted AS EventDate,
				'PointAdjustments' AS SourceTable,
				p.AdjustmentType AS EventType,
				COALESCE(actor.Name, p.AdjustedByUName) AS Actor,
				actor.Email AS ActorEmail,
				COALESCE(target.Name, p.DriverUName) AS Target,
				target.Email AS TargetEmail,
				CONCAT('Points: ', p.AdjustmentPoints, ' | Reason: ', COALESCE(p.AdjustmentReason, '')) AS Details,
				COALESCE(s_actor.Name, '') AS SponsorName,
				COALESCE(s_actor.Email, '') AS SponsorEmail,
				COALESCE(s_actor.Username, '') AS SponsorUsername
			FROM PointAdjustments p
			LEFT JOIN Users actor ON actor.Username = p.AdjustedByUName
			LEFT JOIN Users target ON target.Username = p.DriverUName
			LEFT JOIN Users s_actor ON s_actor.UserType = 'Sponsor' AND s_actor.Username = p.AdjustedByUName
		) audit_rows
	"""

    params = []
    where_clauses = []

    if keyword:
        like = f"%{keyword}%"
        where_clauses.append("""
			(
				SourceTable LIKE %s OR
				EventType LIKE %s OR
				Actor LIKE %s OR
				ActorEmail LIKE %s OR
				Target LIKE %s OR
				TargetEmail LIKE %s OR
				Details LIKE %s
			)
		""")
        params.extend([like, like, like, like, like, like, like])

    if sponsor_filter:
        sponsor_like = f"%{sponsor_filter}%"
        where_clauses.append("""
			(
				SponsorName LIKE %s OR
				SponsorEmail LIKE %s OR
				SponsorUsername LIKE %s
			)
		""")
        params.extend([sponsor_like, sponsor_like, sponsor_like])

    if start_date:
        where_clauses.append("DATE(EventDate) >= %s")
        params.append(start_date)

    if end_date:
        where_clauses.append("DATE(EventDate) <= %s")
        params.append(end_date)

    if category_filter:
        where_clauses.append("SourceTable = %s")
        params.append(category_filter)

    if where_clauses:
        base_query += " WHERE " + " AND ".join(where_clauses)

    count_query = f"""
		SELECT COUNT(*) AS totalRows
		FROM ({base_query}) counted_audit_rows
	"""

    rowTotal = selectDb(count_query, tuple(params)) or [{"totalRows": 0}]
    totalRows = rowTotal[0]["totalRows"] if rowTotal else 0
    numPages = max(1, math.ceil(totalRows / rowsPerPage))

    base_query += " ORDER BY EventDate DESC"

    if export_format == "csv":
        rows = selectDb(base_query, tuple(params)) or []
        return build_csv_response(
            "audit_logs.csv",
            [
                "EventDate",
                "SourceTable",
				"EventType",
				"Actor",
				"ActorEmail",
				"Target",
				"TargetEmail",
				"Details"
			],
			rows
		)

    paged_query = base_query + " LIMIT %s OFFSET %s"
    rows = selectDb(paged_query, tuple(list(params) + [rowsPerPage, offset])) or []

    if export_format == "csv":
        return build_csv_response(
            "audit_logs.csv",
            ["EventDate", "SourceTable", "EventType", "Actor", "Target", "Details"],
            rows
        )

    nav = "orgnav.html" if session.get("Organization") else "activenav.html"

    queryString = urlencode({
	"q": keyword,
	"sponsor": sponsor_filter,
	"start": start_date,
	"end": end_date,
	"category": category_filter,
	"pageCount": rowsPerPage
	})

    return render_template(
        "audit_logs.html",
		layout=nav,
		rows=rows,
		keyword=keyword,
		sponsorFilter=sponsor_filter,
		startDate=start_date,
		endDate=end_date,
		categoryFilter=category_filter,
		page=page,
		pageNum=range(1, numPages + 1),
		pageRows=rowsPerPage,
		queryString=queryString
	)

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
		updateDb("DELETE FROM DriverOrganizations WHERE DriverID = %s", (UserID,))
	updateDb("DELETE FROM Users WHERE UserID = %s", (UserID,))
	
	flash("User deleted successfully.", "success")
	return redirect(f"/{accountType}/users")


def get_admin_dashboard_summary():
    sponsors_row = paramQueryDb("""
        SELECT COUNT(*) AS total
        FROM Users
        WHERE UserType = 'Sponsor'
    """, ()) or {"total": 0}

    drivers_row = paramQueryDb("""
        SELECT COUNT(*) AS total
        FROM Users
        WHERE UserType = 'Driver'
    """, ()) or {"total": 0}

    pending_apps_row = paramQueryDb("""
        SELECT COUNT(*) AS total
        FROM OrganizationApplications
        WHERE ApplicationStatus = 'Pending'
    """, ()) or {"total": 0}

    organizations_row = paramQueryDb("""
        SELECT COUNT(*) AS total
        FROM Organizations
    """, ()) or {"total": 0}

    return {
        "sponsors": int(sponsors_row.get("total") or 0),
        "drivers": int(drivers_row.get("total") or 0),
        "pending_applications": int(pending_apps_row.get("total") or 0),
        "organizations": int(organizations_row.get("total") or 0),
    }

#The different website pages
@application.route("/")
def home():
	if 'UserID' in session:
		getOrganization()
		if session.get("Organization") != None and session.get("role") != "Sponsor":
			session["Organization"] = None

		driver_point_summary = None
		admin_dashboard_summary = None

		if session.get("role") == "Driver" and session.get("OrgID"):
			try:
				driver_point_summary = get_driver_point_history(
					session["UserID"],
					session["OrgID"],
					limit=5
				)
			except Exception as e:
				print("driver_point_summary skipped:", e)

		if session.get("role") == "Admin":
			try:
				admin_dashboard_summary = get_admin_dashboard_summary()
			except Exception as e:
				print("admin_dashboard_summary skipped:", e)

		return render_template(
			"home.html",
			layout="activenav.html",
			driver_point_summary=driver_point_summary,
			admin_dashboard_summary=admin_dashboard_summary
		)

	return render_template(
		"home.html",
		layout="nav.html",
		driver_point_summary=None,
		admin_dashboard_summary=None
	)

"""
This is the about page. Right now it serves as the landing page. Later this will
need to be changed to have a different route. '@application.route("/about/")'
for example.
"""
@application.route("/about")
def about():
    aboutInfo = get_about_info()

    if 'UserID' in session:
        return render_template(
            "about.html",
            layout="activenav.html",
            accountType=session['role'],
            Team=aboutInfo['TeamNum'],
            Version=aboutInfo['VersionNum'],
            Release=aboutInfo['ReleaseDate'],
            Name=aboutInfo['ProductName'],
            Description=aboutInfo['ProductDescription']
        )

    return render_template(
        "about.html",
        layout="nav.html",
        accountType="Driver",
        Team=aboutInfo['TeamNum'],
        Version=aboutInfo['VersionNum'],
        Release=aboutInfo['ReleaseDate'],
        Name=aboutInfo['ProductName'],
        Description=aboutInfo['ProductDescription']
    )

@application.route('/about/export')
def about_export():
    guard = require_admin()
    if guard:
        return guard

    aboutInfo = get_about_info()
    format_type = request.args.get('format', 'json').lower()

    if format_type == 'csv':
        row = {
            'TeamNum': aboutInfo.get('TeamNum', ''),
            'VersionNum': aboutInfo.get('VersionNum', ''),
            'ReleaseDate': aboutInfo.get('ReleaseDate', ''),
            'ProductName': aboutInfo.get('ProductName', ''),
            'ProductDescription': aboutInfo.get('ProductDescription', '')
        }
        return build_csv_response(
            'about_page_export.csv',
            ['TeamNum', 'VersionNum', 'ReleaseDate', 'ProductName', 'ProductDescription'],
            [row]
        )

    return jsonify(aboutInfo)

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

@application.route("/bugReport")
def bugReport():
	prevPage = request.referrer
	layout = "orgnav.html" if session.get("OrgID") else "activenav.html"
	return render_template("bugReport.html", layout=layout, prevPage=prevPage)


@application.route("/support")
def support():
	return redirect(url_for("bugReport"))

@application.route("/bugReport", methods=["POST"])
def postBugReport():
	title = request.form.get("title").strip()
	description = request.form.get("description").strip()
	severity = request.form.get("severityType")
	prevPage = request.form.get("prevPage")

	if not title:
		flash("Title is required.", "validation")
		return redirect(url_for("bugReport"))

	if not description:
		flash("Description is required.", "validation")
		return redirect(url_for("bugReport"))

	updateDb("""INSERT INTO BugReports (Title, Description, Severity)
				VALUES (%s, %s, %s)""", (title, description, severity))
	
	return redirect(prevPage or url_for("home"))

@application.route("/profile")
def profile():
    if "UserID" not in session:
        return redirect(url_for("login"))

    profile = paramQueryDb(
        "SELECT Name, Email, Username, PhoneNumber FROM Users WHERE UserID = %s",
        (session["UserID"],)
    )

    profile = decrypt_fields(profile, ["PhoneNumber"])

    profile["ShippingAddress"] = session.get("shipping_address", {})
    profile["BillingAddress"] = session.get("billing_address", {})

    return render_template("profile.html", layout="activenav.html", profile=profile)

@application.route("/profile/edit")
def editProfile():
    if "UserID" not in session:
        return redirect(url_for("login"))

    user = paramQueryDb("""
        SELECT UserType, UserID, Name, Email, Username, PhoneNumber
        FROM Users
        WHERE UserID=%s
    """, (session["UserID"],))

    user = decrypt_fields(user, ["PhoneNumber"])

    return render_template("editProfile.html", user=user)

@application.route("/profile/edit", methods=["POST"])
def registerProfileEdits():
    if "UserID" not in session:
        return redirect(url_for("login"))

    Name = request.form.get("name", "").strip()
    Username = request.form.get("username", "").strip()
    Email = request.form.get("email", "").strip()
    PhoneNumber = request.form.get("phoneNum", "").strip()

    CurrentPassword = request.form.get("currentPassword", "")
    NewPassword = request.form.get("newPassword", "")
    ConfirmNewPassword = request.form.get("confirmNewPassword", "")

    user = paramQueryDb("""
        SELECT UserID, Name, Email, Username, PhoneNumber, Password_hash
        FROM Users
        WHERE UserID=%s
    """, (session["UserID"],))

    if not user:
        flash("User not found.", "validation")
        return redirect(url_for("profile"))

    user = decrypt_fields(user, ["PhoneNumber"])

    update_fields = []
    update_vals = []

    if Username and Username != user["Username"]:
        exists = paramQueryDb(
            "SELECT UserID FROM Users WHERE Username=%s AND UserID<>%s",
            (Username, session["UserID"])
        )
        if exists:
            flash("That username is already taken.", "username")
            return redirect(url_for("editProfile"))
        update_fields.append("Username=%s")
        update_vals.append(Username)

    if Email and Email != user["Email"]:
        exists = paramQueryDb(
            "SELECT UserID FROM Users WHERE Email=%s AND UserID<>%s",
            (Email, session["UserID"])
        )
        if exists:
            flash("That email is already in use.", "email")
            return redirect(url_for("editProfile"))

        if not CurrentPassword or not check_password_hash(user["Password_hash"], CurrentPassword):
            flash("Current password is required to change email.", "password")
            return redirect(url_for("editProfile"))

        update_fields.append("Email=%s")
        update_vals.append(Email)

    if Name and Name != user["Name"]:
        update_fields.append("Name=%s")
        update_vals.append(Name)

    if PhoneNumber != (user.get("PhoneNumber") or ""):
        update_fields.append("PhoneNumber=%s")
        update_vals.append(encrypt_value(PhoneNumber) if PhoneNumber else None)

    if NewPassword or ConfirmNewPassword:
        if not CurrentPassword or not check_password_hash(user["Password_hash"], CurrentPassword):
            flash("Current password is required to change password.", "password")
            return redirect(url_for("editProfile"))

        if NewPassword != ConfirmNewPassword:
            flash("New passwords do not match.", "password")
            return redirect(url_for("editProfile"))

        errors = password_policy_errors(NewPassword)
        if errors:
            flash(" ".join(errors), "password")
            return redirect(url_for("editProfile"))

        update_fields.append("Password_hash=%s")
        update_vals.append(generate_password_hash(NewPassword, method="pbkdf2:sha256"))

        try:
            log_password_event("password_changed", actor_user_id=session["UserID"], target_user_id=session["UserID"])
        except Exception as e:
            print("password change log skipped:", e)

    if not update_fields:
        flash("No changes were made.", "registered")
        return redirect(url_for("profile"))

    update_vals.append(session["UserID"])
    updateDb(f"UPDATE Users SET {', '.join(update_fields)} WHERE UserID=%s", tuple(update_vals))

    flash("Profile updated successfully.", "success")
    return redirect(url_for("profile"))

@application.route("/settings")
def settings():
	hasPhoneNum = False
	prefs = selectDb("""
			SELECT PrefCommMethod, EssentialNotifsOnly, PhoneNumber, ThemePref, FontPref
			FROM Users 
			WHERE UserID=%s
			ORDER BY UserID
		""", (session["UserID"],))
	if prefs[0]["PhoneNumber"] != None:
		hasPhoneNum = True
	return render_template("settings.html", layout = "activenav.html", themePref=prefs[0]["ThemePref"] ,fontPref=prefs[0]["FontPref"] ,
							currentPref=prefs[0]["PrefCommMethod"], hasPhoneNum=hasPhoneNum, essentialNotifs=prefs[0]["EssentialNotifsOnly"],
							shippingAddress=session.get("shipping_address", {}), billingAddress=session.get("billing_address", {})) 

@application.route("/settings/addresses", methods=["POST"])
def save_settings_addresses():
    if "UserID" not in session:
        return redirect(url_for("login"))

    shipping_street = request.form.get("shippingStreet", "").strip()
    shipping_city = request.form.get("shippingCity", "").strip()
    shipping_state = request.form.get("shippingState", "").strip()

    billing_street = request.form.get("billingStreet", "").strip()
    billing_city = request.form.get("billingCity", "").strip()
    billing_state = request.form.get("billingState", "").strip()

    session["shipping_address"] = {
        "street": shipping_street,
        "city": shipping_city,
        "state": shipping_state
    }

    session["billing_address"] = {
        "street": billing_street,
        "city": billing_city,
        "state": billing_state
    }

    flash("Address settings updated.", "success")
    return redirect(url_for("settings"))

@application.route("/settings/appearance", methods=["POST"])
def settingsAppearance():
    theme_pref = request.form.get("themePref", "system")
    font_pref = request.form.get("fontPref", "md")

    allowed_themes = {"system", "light", "dark"}
    allowed_fonts = {"sm", "md", "lg", "xl"}

    if theme_pref not in allowed_themes:
        theme_pref = "system"
    if font_pref not in allowed_fonts:
        font_pref = "md"

    updateDb(
        "UPDATE Users SET ThemePref=%s, FontPref=%s WHERE UserID=%s",
        (theme_pref, font_pref, session["UserID"])
    )

    flash("Appearance settings updated.", "success")
    return redirect(url_for("settings"))

@application.route("/settings/communicationPreference", methods=["POST"])
def communicationPreference():
	commPref = request.form.get("commPref")
	updateDb(f"UPDATE Users SET PrefCommMethod=%s WHERE UserID=%s", (commPref, session["UserID"]))
	return redirect(url_for("settings"))

@application.route("/settings/essentialNotifications", methods=["POST"])
def essentialNotifications():
	essentialNotif = 1 if request.form.get("essentialNotif") else 0
	updateDb(f"UPDATE Users SET EssentialNotifsOnly=%s WHERE UserID=%s", (essentialNotif, session["UserID"]))
	return redirect(url_for("settings"))

@application.route("/<int:UserID>/organizations")
def DriverOrganizations(UserID):
	session["Organization"]	= None

	q = request.args.get("q", "").strip()
	like = f"%{q}%"
	
	page = request.args.get("page", 1, type=int)
	rowsPerPage = request.args.get("pageCount", 10, type=int)
	offset = (page - 1) * rowsPerPage

	if q:
		rowTotal = selectDb("""
			SELECT COUNT(*) AS totalRows
			FROM DriverOrganizations d LEFT JOIN Organizations o ON d.OrganizationID = o.OrganizationID 
			WHERE o.Name LIKE %s AND d.DriverID = %s
			ORDER BY Name
		""", (like, UserID))
		orgs = selectDb("""
			SELECT d.OrganizationID, o.Name, o.Status
			FROM DriverOrganizations d LEFT JOIN Organizations o ON d.OrganizationID = o.OrganizationID  
			WHERE Name LIKE %s AND d.DriverID = %s
			ORDER BY o.Name
			LIMIT %s OFFSET %s
		""", (like, UserID, rowsPerPage, offset))
	else:
		rowTotal = selectDb("""
			SELECT COUNT(*) AS totalRows
			FROM DriverOrganizations d LEFT JOIN Organizations o ON d.OrganizationID = o.OrganizationID 
			WHERE d.DriverID = %s
			ORDER BY Name
		""", (UserID,))
		orgs = selectDb("""
			SELECT d.OrganizationID, o.Name, o.Status
			FROM DriverOrganizations d LEFT JOIN Organizations o ON d.OrganizationID = o.OrganizationID 
			WHERE d.DriverID = %s
			ORDER BY Name
			LIMIT %s OFFSET %s
		""", (UserID, rowsPerPage, offset))
	
	numPages = math.ceil(rowTotal[0]["totalRows"] / rowsPerPage)
	
	return render_template("orgList.html", layout="activenav.html", orgs=orgs, q=q, page=page, pageNum=range(1, numPages + 1), pageRows=rowsPerPage, status="Approved")

@application.route("/organizations")
def organizations():
	guard = require_admin()
	if guard: 
		return guard

	session["Organization"]	= None
	
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
			SELECT OrganizationID, Name, Status
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
			SELECT OrganizationID, Name, Status
			FROM Organizations
			ORDER BY Name
			LIMIT %s OFFSET %s
		""", (rowsPerPage, offset))
	
	numPages = math.ceil(rowTotal[0]["totalRows"] / rowsPerPage)
	
	return render_template("orgList.html", layout="activenav.html", orgs=orgs, q=q, page=page, pageNum=range(1, numPages + 1), pageRows=rowsPerPage, status="orgs")

@application.route("/organizations/<int:OrgID>/deactivate", methods=["POST"])
def organizationDeactivate(OrgID):
	updateDb("UPDATE Organizations SET Status = %s WHERE OrganizationID = %s", ("Inactive", OrgID))
	
	flash("Organization deactivated successfully.", "success")
	return redirect(url_for("organizations"))

@application.route("/organizations/<int:OrgID>/activate", methods=["POST"])
def organizationActivate(OrgID):
	updateDb("UPDATE Organizations SET Status = %s WHERE OrganizationID = %s", ("Active", OrgID))
	
	flash("Organization activated successfully.", "success")
	return redirect(url_for("organizations"))

@application.route("/organizations/<int:OrgID>/view")
def organizationView(OrgID):
	org = ""
	if session['role'] == "Driver":
		org = paramQueryDb("""SELECT o.Name, o.OrganizationID, d.TotalPoints
							FROM DriverOrganizations d JOIN Organizations o ON d.OrganizationID = o.OrganizationID
							WHERE d.OrganizationID = %s and d.DriverID = %s""", (OrgID, session["UserID"]))
		
		session["Points"] = org["TotalPoints"]
	else:
		org = paramQueryDb("SELECT Name, OrganizationID FROM Organizations WHERE OrganizationID = %s", (OrgID,))
	
	if not org: 
		flash("Organization not found.", "validation")
		return redirect(url_for("organizations"))

	session["Organization"] = org["Name"]
	session["OrgID"] = org["OrganizationID"]
	return redirect(url_for("organization"))

@application.route("/organizations/<int:OrgID>/edit", methods=["POST"])
def organizationEdit(OrgID):
	newName = request.form.get("newName")
	updateDb("UPDATE Organizations SET Name = %s WHERE OrganizationID = %s", (newName, OrgID))
	return redirect(url_for("organizations"))

@application.route("/organizations/<int:OrgID>/delete", methods=["POST"])
def organizationDelete(OrgID):
	updateDb("UPDATE DriverOrganizations SET OrganizationID = %s WHERE OrganizationID = %s", ("0", OrgID))
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
			LEFT JOIN DriverOrganizations d ON u.UserID = d.DriverID
			LEFT JOIN Organizations o ON o.OrganizationID=COALESCE(s.OrganizationID, d.OrganizationID)
			WHERE (u.Name LIKE %s OR u.Email LIKE %s OR u.Username LIKE %s) AND 
				  (u.UserType = "Sponsor" OR u.UserType = "Driver") AND 
				  (o.Name = %s)
			ORDER BY o.Name
		""", (like, like, like, session['Organization']))
		users = selectDb("""
			SELECT u.UserID, u.UserType, u.UserID, u.Name, u.Email, u.Username, o.Name, d.TotalPoints
			FROM Users u LEFT JOIN Sponsors s ON u.UserID = s.SponsorID 
			LEFT JOIN DriverOrganizations d ON u.UserID = d.DriverID
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
			LEFT JOIN DriverOrganizations d ON u.UserID = d.DriverID
			LEFT JOIN Organizations o ON o.OrganizationID=COALESCE(s.OrganizationID, d.OrganizationID)
			WHERE (u.UserType = "Sponsor" OR u.UserType = "Driver") AND 
				  (o.Name = %s)
			ORDER BY o.Name
		""", (session['Organization'],))
		users = selectDb("""
			SELECT u.UserID, u.UserType, u.UserID, u.Name, u.Email, u.Username, o.Name, d.TotalPoints
			FROM Users u LEFT JOIN Sponsors s ON u.UserID = s.SponsorID 
			LEFT JOIN DriverOrganizations d ON u.UserID = d.DriverID
			LEFT JOIN Organizations o ON o.OrganizationID=COALESCE(s.OrganizationID, d.OrganizationID)
			WHERE (u.UserType = "Sponsor" OR u.UserType = "Driver") AND 
				  (o.Name = %s)
			ORDER BY o.Name
			LIMIT %s OFFSET %s
		""", (session['Organization'], rowsPerPage, offset))

	numPages = math.ceil(rowTotal[0]["totalRows"] / rowsPerPage)
	
	return render_template("userList.html", layout="orgnav.html", users=users, q=q, accountType='organization', use="organization", canImpersonate=(session.get("role") == "Sponsor" and not is_impersonating()), page=page, pageNum=range(1, numPages + 1), pageRows=rowsPerPage)

@application.route("/organization/users/<int:UserID>/assume", methods=["POST"])
def assume_driver_identity(UserID):
    guard = require_sponsor()
    if guard:
        return guard

    if session.get("impersonating"):
        flash("Exit the current impersonation session first.", "validation")
        return redirect(url_for("organizationUsers"))

    driver = paramQueryDb("""
        SELECT u.UserID, u.UserType, u.Name, o.Name AS OrganizationName
        FROM Users u
        JOIN DriverOrganizations d ON u.UserID = d.DriverID
        JOIN Organizations o ON d.OrganizationID = o.OrganizationID
        WHERE u.UserID=%s
          AND u.UserType='Driver'
          AND o.Name=%s
    """, (UserID, session.get("Organization")))

    if not driver:
        flash("Driver not found in your organization.", "validation")
        return redirect(url_for("organizationUsers"))

    session["impersonating"] = True
    session["original_UserID"] = session.get("UserID")
    session["original_role"] = session.get("role")
    session["original_Organization"] = session.get("Organization")
    session["original_OrgID"] = session.get("OrgID", 0)

    session["UserID"] = driver["UserID"]
    session["role"] = "Driver"
    session["Organization"] = driver["OrganizationName"]

    org = paramQueryDb("SELECT OrganizationID FROM Organizations WHERE Name=%s", (driver["OrganizationName"],))
    session["OrgID"] = org["OrganizationID"] if org else 0

    flash(f"Now viewing the app as {driver['Name']}.", "success")
    return redirect(url_for("home"))

@application.route("/impersonation/exit", methods=["POST"])
def exit_impersonation():
    if not session.get("impersonating"):
        flash("No impersonation session is active.", "validation")
        return redirect(url_for("home"))

    session["UserID"] = session.get("original_UserID")
    session["role"] = session.get("original_role")
    session["Organization"] = session.get("original_Organization")
    session["OrgID"] = session.get("original_OrgID", 0)

    session.pop("impersonating", None)
    session.pop("original_UserID", None)
    session.pop("original_role", None)
    session.pop("original_Organization", None)
    session.pop("original_OrgID", None)

    flash("Returned to your sponsor view.", "success")
    return redirect(url_for("home"))

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
        JOIN DriverOrganizations d ON u.UserID = d.DriverID
		JOIN Organizations o ON d.OrganizationID = o.OrganizationID
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
		JOIN DriverOrganizations d ON u.UserID = d.DriverID
		WHERE d.DriverID=%s AND d.OrganizationID = %s AND u.UserType='Driver'
		""", (UserID, session["OrgID"]))

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
	updateDb("UPDATE DriverOrganizations SET TotalPoints=%s WHERE DriverID=%s", (newTotal, UserID))

	# Try to record feedback in an audit table if it exists (won't crash if not)
	user = paramQueryDb("""SELECT Username FROM Users WHERE UserID = %s""", (session["UserID"],))
	organization = paramQueryDb("""SELECT OrganizationID FROM Organizations WHERE Name = %s""", (session["Organization"],))
	try:
		updateDb("""
		INSERT INTO PointAdjustments(OrganizationID, AdjustedByUName, DriverUName, AdjustmentType, DriverTotalPoints, AdjustmentPoints, AdjustmentReason, DateAdjusted)
		VALUES (%s, %s, %s, %s, %s, %s, %s)
		""", (organization.get("OrganizationID"), user.get("Username"), driver["Username"], adjustmentType, newTotal, points, reason, datetime.now()))
	except Exception as e:
		# If table doesn't exist, keep app working
		print("PointDeductions insert skipped:", e)

	flash(f"Adjusted Points by {points}. New total: {newTotal}.", "success")
	return redirect(url_for("organizationUsers"))

@application.route("/organization/users/<int:UserID>/remove", methods=["POST"])
def removeOrgUser(UserID):
	user = selectDb("""SELECT UserType FROM Users WHERE UserID = %s""", (UserID,))
	if user[0]["UserType"] == "Sponsor":
		updateDb("""UPDATE Sponsors SET OrganizationID = %s WHERE SponsorID = %s""", (None, UserID,))
	elif user[0]["UserType"] == "Driver":
		updateDb("""UPDATE DriverOrganizations SET OrganizationID = %s WHERE DriverID = %s""", (None, UserID,))
	return redirect(url_for("organizationUsers"))

@application.route("/organization/apply")
def apply():
	#guard = require_admin()
	#if guard: 
	#	return guard
	
	q = request.args.get("q", "").strip()
	like = f"%{q}%"
	
	page = request.args.get("page", 1, type=int)
	rowsPerPage = request.args.get("pageCount", 10, type=int)
	offset = (page - 1) * rowsPerPage

	user = paramQueryDb("SELECT Username FROM Users WHERE UserID=%s", (session["UserID"],))
	username = user["Username"]

	if q:
		rowTotal = selectDb("""
			SELECT COUNT(*) AS totalRows
			FROM Organizations o LEFT JOIN OrganizationApplications a ON a.OrganizationID = o.OrganizationID AND a.DriverUName = %s
			WHERE Name LIKE %s
			ORDER BY Name
		""", (username, like))
		orgs = selectDb("""
			SELECT o.OrganizationID, Name, Status,
				CASE
					WHEN a.ApplicationStatus = "Pending" THEN 'Applied'
					WHEN a.ApplicationStatus = "Pending" THEN 'Accepted'
					WHEN a.ApplicationStatus = "Pending" THEN 'Rejected'
					ELSE "NotApplied"
				END AS appStatus
			FROM Organizations o LEFT JOIN OrganizationApplications a ON a.OrganizationID = o.OrganizationID AND a.DriverUName = %s
			WHERE Name LIKE %s
			ORDER BY Name
			LIMIT %s OFFSET %s
		""", (username, like, rowsPerPage, offset))
	else:
		rowTotal = selectDb("""
			SELECT COUNT(*) AS totalRows
			FROM Organizations o LEFT JOIN OrganizationApplications a ON a.OrganizationID = o.OrganizationID AND a.DriverUName = %s
			ORDER BY Name
		""", (username, ))
		orgs = selectDb("""
			SELECT o.OrganizationID, Name, Status,
				CASE
					WHEN a.ApplicationStatus = "Pending" THEN 'Applied'
					WHEN a.ApplicationStatus = "Accepted" THEN 'Accepted'
					WHEN a.ApplicationStatus = "Rejected" THEN 'Rejected'
					ELSE "NotApplied"
				END AS appStatus
			FROM Organizations o LEFT JOIN OrganizationApplications a ON a.OrganizationID = o.OrganizationID AND a.DriverUName = %s
			ORDER BY Name
			LIMIT %s OFFSET %s
		""", (username, rowsPerPage, offset))
	
	numPages = math.ceil(rowTotal[0]["totalRows"] / rowsPerPage)
	
	return render_template("orgList.html", layout="activenav.html", orgs=orgs, q=q, page=page, pageNum=range(1, numPages + 1), pageRows=rowsPerPage, status="Applying")

@application.route("/organization/apply/<int:OrgID>")
def applyPost(OrgID):
	user = paramQueryDb("""SELECT Username FROM Users WHERE UserID = %s""", (session['UserID'],))
	org = paramQueryDb("""SELECT Name FROM Organizations WHERE OrganizationID = %s""", (OrgID,))
	timeApplied = datetime.now()

	updateDb("""INSERT INTO OrganizationApplications (OrganizationID, DriverUName, ApplicationStatus, DateApplied)
				VALUES (%s, %s, %s, %s)""", (OrgID, user['Username'], "Pending", timeApplied))

	org_name = org["Name"] if org else "the organization"
	flash(f"You have applied for enrollment in {org_name}.", "enrolled")
	return redirect(url_for("apply"))

@application.route("/organization/apply/cancel/<int:OrgID>")
def cancelPost(OrgID):
	user = paramQueryDb("""SELECT Username FROM Users WHERE UserID = %s""", (session['UserID'],))
	updateDb("""DELETE FROM OrganizationApplications WHERE DriverUName = %s AND OrganizationID = %s""", (user["Username"], OrgID))
	return redirect(url_for("apply"))

@application.route("/organization/applications")
def applications():
	if "UserID" not in session or session.get("role") not in ["Sponsor", "Admin"]:
		return redirect(url_for("home"))

	if not session.get("OrgID"):
		flash("Organization not found.", "validation")
		return redirect(url_for("organization"))

	q = request.args.get("q", "").strip()
	like = f"%{q}%"

	page = request.args.get("page", 1, type=int)
	rowsPerPage = request.args.get("pageCount", 10, type=int)
	offset = (page - 1) * rowsPerPage

	if q:
		rowTotal = selectDb("""
			SELECT COUNT(*) AS totalRows
			FROM OrganizationApplications a
			JOIN Users u ON a.DriverUName = u.Username
			JOIN Organizations o ON a.OrganizationID = o.OrganizationID
			WHERE (u.Name LIKE %s OR u.Email LIKE %s OR u.Username LIKE %s)
			AND u.UserType = "Driver"
			AND a.OrganizationID = %s
			AND a.ApplicationStatus = "Pending"
		""", (like, like, like, session["OrgID"]))

		users = selectDb("""
			SELECT u.UserID, u.Username, u.Name, u.Email, u.UserType, a.DateApplied, o.Name
			FROM OrganizationApplications a
			JOIN Users u ON a.DriverUName = u.Username
			JOIN Organizations o ON a.OrganizationID = o.OrganizationID
			WHERE (u.Name LIKE %s OR u.Email LIKE %s OR u.Username LIKE %s)
			AND u.UserType = "Driver"
			AND a.OrganizationID = %s
			AND a.ApplicationStatus = "Pending"
			ORDER BY a.DateApplied DESC, u.Name
			LIMIT %s OFFSET %s
		""", (like, like, like, session["OrgID"], rowsPerPage, offset))
	else:
		rowTotal = selectDb("""
			SELECT COUNT(*) AS totalRows
			FROM OrganizationApplications a
			JOIN Users u ON a.DriverUName = u.Username
			WHERE u.UserType = "Driver"
			AND a.OrganizationID = %s
			AND a.ApplicationStatus = "Pending"
		""", (session["OrgID"],))

		users = selectDb("""
			SELECT u.UserID, u.Username, u.Name, u.Email, u.UserType, a.DateApplied
			FROM OrganizationApplications a
			JOIN Users u ON a.DriverUName = u.Username
			WHERE u.UserType = "Driver"
			AND a.OrganizationID = %s
			AND a.ApplicationStatus = "Pending"
			ORDER BY a.DateApplied DESC, u.Name
			LIMIT %s OFFSET %s
		""", (session["OrgID"], rowsPerPage, offset))

	numPages = math.ceil(rowTotal[0]["totalRows"] / rowsPerPage)

	return render_template("userList.html", layout="orgnav.html", users=users, q=q, accountType='organization', use="application", page=page, pageNum=range(1, numPages + 1), pageRows=rowsPerPage)

@application.route("/organization/applications/<int:UserID>/accept", methods=["POST"])
def acceptedApplications(UserID):
	reason = request.form.get("acceptReason")
	user = paramQueryDb("""SELECT Username FROM Users WHERE UserID = %s""", (session['UserID'],))
	driver = paramQueryDb("""SELECT Username FROM Users WHERE UserID = %s""", (UserID,))
	timeJoined= datetime.now()
	updateDb("""UPDATE OrganizationApplications SET ApplicationStatus = %s, ReviewedByUName = %s, ReviewReason = %s WHERE DriverUName = %s AND OrganizationID = %s""", ("Accepted", user["Username"], reason, driver["Username"], session["OrgID"]))
	updateDb("""
		UPDATE DriverOrganizations
		SET OrganizationID = %s
		WHERE DriverID = %s
	""", (session["OrgID"], UserID))

	try:
		updateDb("""
			INSERT INTO DriverOrganizations (OrganizationID, DriverID)
			VALUES (%s, %s)
		""", (session["OrgID"], UserID))
	except Exception as e:
		print("DriverOrganizations insert skipped:", e)
	return redirect(url_for("applications"))

@application.route("/organization/applications/<int:UserID>/reject", methods=["POST"])
def rejectedApplications(UserID):
	reason = request.form.get("rejectReason")
	user = paramQueryDb("""SELECT Username FROM Users WHERE UserID = %s""", (session['UserID'],))
	driver = paramQueryDb("""SELECT Username FROM Users WHERE UserID = %s""", (UserID,))
	updateDb("""UPDATE OrganizationApplications SET ApplicationStatus = %s, ReviewedByUName = %s, ReviewReason = %s WHERE DriverUName = %s AND OrganizationID = %s""", ("Rejected", user["Username"], reason, driver["Username"], session["OrgID"]))
	return redirect(url_for("applications"))

@application.route("/organization/<int:OrgID>/leave", methods=["POST"])
def organization_leave(OrgID):
    if "UserID" not in session:
        flash("Please login first.", "auth")
        return redirect(url_for("login"))

    if session.get("role") != "Driver":
        flash("Drivers only.", "auth")
        return redirect(url_for("organization"))

    updateDb(
		"DELETE FROM DriverOrganizations WHERE OrganizationID=%s AND DriverID=%s",
		(OrgID, session["UserID"])
	)

    session.pop("Organization", None)
    flash("You left the organization.", "success")
    return redirect(url_for("home"))

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
		if session['role'] == "Admin" and session["Organization"] == None:
			return render_template("catalog.html", layout="activenav.html")
		return render_template("catalog.html", layout="orgnav.html")
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

	#make the price equal to the price in dollars divided by the point value
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
	if "UserID" in session and session.get("role")=="Driver" and "OrgID" in session:
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

		return render_template("wishlist.html", layout="orgnav.html", wishlistData=wishlistData)
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

@application.route("/cart/update", methods=["POST"])
def updateCart():
	if "UserID" in session and "OrgID" in session:
		data = request.get_json()

		amount = data.get("amount")
		productID = data.get("productID")

		userID = session.get("UserID")
		orgID = session.get("OrgID")

		#make sure amount is an int, above 0, and less than or equal to stock amount
		if not isinstance(amount, int):
			return jsonify({"message": "The value provided was not an integer"}), 400
		if amount<1:
			return jsonify({"message": "The value provided was below 1"}), 400
		if amount>(getProductData(productID).get("stock")):
			return jsonify({"message": "The value was greater than the amount of stock available"}), 400


		updateCartQuery = """
			UPDATE Cart
			SET amount=%s
			WHERE
				userID=%s
				AND orgID=%s
				AND productID=%s
		"""
		try:
			updateDb(query=updateCartQuery, params=(amount, userID, orgID, productID))
		except Exception as e:
			print(e)
			return jsonify({"message": "Error updating amount"}), 400
		
		productData = getProductData(productID)
		productPrice = adjustPrice([productData])[0].get("price")
		
		newPriceDisplay = productPrice*amount

		return jsonify({"message": "Success", "newPriceDisplay": newPriceDisplay}), 200
	return jsonify({"message": "Permission error"}), 400

@application.route("/cart/remove", methods=["POST"])
def removeFromCart():
	if "UserID" in session and "OrgID" in session:
		data = request.get_json()

		productID = data.get("productID")

		userID = session.get("UserID")
		orgID = session.get("OrgID")

		deleteFromCartQuery = """
			DELETE FROM Cart
			WHERE
				userID=%s
				AND orgID=%s
				AND productID=%s
		"""
		try:
			updateDb(query=deleteFromCartQuery, params=(userID, orgID, productID))
		except Exception as e:
			print(e)
			return jsonify({"message": "Error removing product from cart"}), 400
		return redirect(url_for("cart"))

	return jsonify({"message": "Permission error"}), 400

def getProductData(id):
	response = requests.get(f"https://dummyjson.com/products/{id}")
	if not response.ok:
		return None
	return response.json()


@application.route("/cart")
def cart():
	if "UserID" in session and "OrgID" in session:
		userID = session.get("UserID")
		orgID = session.get("OrgID")

		getCartItemsQuery = """
			SELECT productID, amount
			FROM Cart
			WHERE
				userID=%s
				AND orgID=%s
		"""
		rows = selectDb(query=getCartItemsQuery, params=(userID, orgID))

		#collect just the product ids into a list
		cartProductIds = []
		#collect quantities of products into a list
		cartQuantities = []
		for row in rows:
			cartProductIds.append(row.get("productID"))
			cartQuantities.append(row.get("amount"))

		cartProductData = []
		for productId in cartProductIds:
			cartProductData.append(getProductData(productId))

		cartProductData = adjustPrice(cartProductData)

		for i, amount in enumerate(cartQuantities):
			cartProductData[i]["quantity"] = amount

		return render_template("cart.html", layout="orgnav.html", cartProductData=cartProductData)
	return redirect(url_for("home"))

@application.route("/product/<int:productID>")
def product_popup(productID):
	productData = getProductData(productID)
	productData = adjustPrice([productData])[0]
	return render_template("product_popup.html", productDetails=productData)

def getCartTotal(userID, orgID):
	getCartItemsQuery = """
		SELECT 
			productID,
			amount
		FROM Cart
		WHERE
			userID=%s
			AND orgID=%s
	"""
	cartItems = selectDb(query=getCartItemsQuery, params=(userID, orgID))
	if not cartItems:
		raise Exception("User has no items in their cart")

	#find the unit price for each product based on org rules
	for product in cartItems:
		productData = getProductData(product["productID"])
		product["price"] = productData.get("price")
	cartItems = adjustPrice(cartItems)

	#calculate total
	total = 0
	for product in cartItems:
		unitPrice = int(product.get("price"))
		quantity = int(product.get("amount"))
		total += (unitPrice*quantity)
	return total

def getDriverPoints():
	#grab the user's point total from db
	userID = session.get("UserID")
	orgID = session.get("OrgID")
	getDriverPointsQuery = """
		SELECT TotalPoints
		FROM DriverOrganizations
		WHERE 
			DriverID=%s
			AND OrganizationID=%s
	"""
	return paramQueryDb(query=getDriverPointsQuery, params=(userID, orgID)).get("TotalPoints",0)

def adjustDriverPoints(driverID, orgID, newPointTotal):
	adjustDriverPointsQuery = """
		UPDATE DriverOrganizations
		SET TotalPoints=%s
		WHERE
			DriverID=%s
			AND OrganizationID=%s
	"""
	updateDb(query=adjustDriverPointsQuery, params=(newPointTotal, driverID, orgID))

def get_driver_org_membership(driverID, orgID):
	return paramQueryDb(
		"""
		SELECT DriverID, OrganizationID, TotalPoints
		FROM DriverOrganizations
		WHERE DriverID=%s AND OrganizationID=%s
		""",
		(driverID, orgID)
	)


def log_redemption_denial(userID, orgID, reason, points_attempted=0):
	try:
		user = paramQueryDb("SELECT Username FROM Users WHERE UserID=%s", (userID,))
		username = user.get("Username") if user else f"user-{userID}"
		membership = get_driver_org_membership(userID, orgID) or {}
		current_points = int(membership.get("TotalPoints") or 0)

		updateDb(
			"""
			INSERT INTO PointAdjustments
			(OrganizationID, AdjustedByUName, DriverUName, AdjustmentType, DriverTotalPoints, AdjustmentPoints, AdjustmentReason, DateAdjusted)
			VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
			""",
			(orgID, username, username, "Denied", current_points, int(points_attempted or 0), reason, datetime.now())
		)
	except Exception as e:
		print("Redemption denial log skipped:", e)


def validate_redemption_request(userID, orgID):
	membership = get_driver_org_membership(userID, orgID)
	if not membership:
		return {
			"ok": False,
			"message": "Redemption blocked because your sponsor affiliation for this organization is missing.",
			"cart": [],
			"total": 0,
			"driver_points": 0
		}

	cartData = getCartData(userID, orgID)
	if not cartData:
		return {
			"ok": False,
			"message": "Your cart is empty.",
			"cart": [],
			"total": 0,
			"driver_points": int(membership.get("TotalPoints") or 0)
		}

	validated_cart = []
	current_total = 0

	for item in cartData:
		productID = item.get("id")
		quantity = int(item.get("quantity") or 0)

		live_product = getProductData(productID)
		if not live_product:
			return {
				"ok": False,
				"message": "A product in your cart could not be loaded right now. Please return to the catalog and try again.",
				"cart": [],
				"total": 0,
				"driver_points": int(membership.get("TotalPoints") or 0)
			}

		live_product = adjustPrice([live_product])[0]
		live_price = int(live_product.get("price") or 0)
		available_stock = int(live_product.get("stock") or 0)

		if available_stock < quantity:
			return {
				"ok": False,
				"message": f"{item.get('title')} is no longer available in the quantity you selected. Please return to the catalog or update your cart.",
				"cart": [],
				"total": 0,
				"driver_points": int(membership.get("TotalPoints") or 0)
			}

		item["price"] = live_price
		item["stock"] = available_stock
		item["availability_label"] = "In Stock" if available_stock > 0 else "Out of Stock"

		validated_cart.append(item)
		current_total += live_price * quantity

	driver_points = int(membership.get("TotalPoints") or 0)

	if current_total > driver_points:
		return {
			"ok": False,
			"message": "You do not have enough points to complete this redemption.",
			"cart": validated_cart,
			"total": current_total,
			"driver_points": driver_points
		}

	return {
		"ok": True,
		"message": "",
		"cart": validated_cart,
		"total": current_total,
		"driver_points": driver_points
	}

@application.route("/cart/checkout")
def checkout():
	if "UserID" not in session or "OrgID" not in session:
		return redirect(url_for("home"))

	userID = session.get("UserID")
	orgID = session.get("OrgID")

	validation = validate_redemption_request(userID, orgID)
	if not validation["ok"]:
		log_redemption_denial(userID, orgID, validation["message"], validation.get("total", 0))
		flash(validation["message"], "validation")
		return redirect(url_for("cart"))

	return render_template("checkout.html", layout="orgnav.html")

def getCartData(userID, orgID):
	getCartItemsQuery = """
		SELECT productID, amount
		FROM Cart
		WHERE
			userID=%s
			AND orgID=%s
	"""
	rows = selectDb(query=getCartItemsQuery, params=(userID, orgID))

	cartProductIds = []
	cartQuantities = []
	for row in rows:
		cartProductIds.append(row.get("productID"))
		cartQuantities.append(row.get("amount"))

	cartProductData = []
	validQuantities = []

	for i, productId in enumerate(cartProductIds):
		product = getProductData(productId)
		if product:
			cartProductData.append(product)
			validQuantities.append(cartQuantities[i])

	if not cartProductData:
		return []

	cartProductData = adjustPrice(cartProductData)

	for i, amount in enumerate(validQuantities):
		cartProductData[i]["quantity"] = amount

	return cartProductData

@application.route("/orders/confirm", methods=["POST"])
def orderConfirmation():
	if "UserID" not in session or "OrgID" not in session:
		return redirect(url_for("home"))

	userID = session.get("UserID")
	orgID = session.get("OrgID")

	validation = validate_redemption_request(userID, orgID)
	if not validation["ok"]:
		log_redemption_denial(userID, orgID, validation["message"], validation.get("total", 0))
		flash(validation["message"], "validation")
		return redirect(url_for("cart"))

	addressDict = {
		"address": request.form.get("address", "").strip(),
		"city": request.form.get("city", "").strip(),
		"state": request.form.get("state", "").strip()
	}

	return render_template(
		"confirm_order.html",
		layout="orgnav.html",
		cart=validation["cart"],
		address=addressDict,
		total=validation["total"],
		driverPoints=validation["driver_points"]
	)

@application.route("/orders", methods=["POST"])
def makeOrder():
	if "UserID" not in session or "OrgID" not in session:
		return redirect(url_for("home"))

	try:
		userID = session.get("UserID")
		orgID = session.get("OrgID")

		validation = validate_redemption_request(userID, orgID)
		if not validation["ok"]:
			log_redemption_denial(userID, orgID, validation["message"], validation.get("total", 0))
			flash(validation["message"], "validation")
			return redirect(url_for("cart"))

		expected_total = int(request.form.get("expected_total") or 0)
		if expected_total != validation["total"]:
			message = f"Your cart total changed from {expected_total} to {validation['total']} points. Please review your order again before confirming."
			log_redemption_denial(userID, orgID, message, validation["total"])
			flash(message, "validation")
			return redirect(url_for("cart"))

		newDriverPointTotal = validation["driver_points"] - validation["total"]
		if newDriverPointTotal < 0:
			message = "This redemption was denied because it would make the point balance go below zero."
			log_redemption_denial(userID, orgID, message, validation["total"])
			flash(message, "validation")
			return redirect(url_for("cart"))

		adjustDriverPoints(userID, orgID, newDriverPointTotal)

		address = request.form.get("address")
		city = request.form.get("city")
		state = request.form.get("state")

		connection = getDbConnection()
		cursor = connection.cursor()
		insertOrderQuery = """
			INSERT INTO Orders
				(userID, orgID, pointTotal, deliveryAddress, deliveryCity, deliveryState, orderTime, estimatedArrival)
			VALUES 
				(%s,%s,%s,%s,%s,%s,%s,%s + INTERVAL 1 WEEK)
		"""
		cursor.execute(
			query=insertOrderQuery,
			args=(userID, orgID, validation["total"], address, city, state, datetime.now(), datetime.now())
		)
		connection.commit()
		orderID = cursor.lastrowid
		cursor.close()

		insertOrderItemQuery = """
			INSERT INTO OrderItems
				(orderID, productID, unitPrice, totalPrice, amount)
			VALUES
				(%s,%s,%s,%s,%s)
		"""
		for item in validation["cart"]:
			productID = item.get("id")
			unitPrice = int(item.get("price") or 0)
			amount = int(item.get("quantity") or 0)
			totalPrice = unitPrice * amount
			updateDb(insertOrderItemQuery, params=(orderID, productID, unitPrice, totalPrice, amount))

		deleteCartItemsQuery = """
			DELETE FROM Cart
			WHERE
				userID=%s
				AND orgID=%s
		"""
		updateDb(query=deleteCartItemsQuery, params=(userID, orgID))

		session["Points"] = newDriverPointTotal
		flash("Purchase successful. Order confirmed.", category="orderConfirmation")

	except Exception as e:
		print(e)
		flash("We could not complete your order right now. Please try again.", "validation")
		return redirect(url_for("checkout"))

	return redirect(url_for("cart"))

@application.route("/orders")
def previousOrders():
	if "UserID" not in session or session.get("role") != "Driver":
		return redirect(url_for("home"))
	userID = session.get("UserID")
	orgID = session.get("OrgID")
	start = request.args.get("start", "").strip()
	end = request.args.get("end", "").strip()
	start_date = parse_iso_date(start) if start else None
	end_date = parse_iso_date(end) if end else None
	if start and not start_date:
		flash("Start date must be a valid date.", "validation")
		start = ""
	if end and not end_date:
		flash("End date must be a valid date.", "validation")
		end = ""
	if start_date and end_date and start_date > end_date:
		flash("Start date cannot be after the end date.", "validation")
		start = ""
		end = ""
		start_date = None
		end_date = None
	getOrdersQuery = """
		SELECT
			orderID,
			pointTotal,
			deliveryAddress,
			deliveryCity,
			deliveryState,
			estimatedArrival,
			orderTime
		FROM Orders
		WHERE
			userID=%s
			AND orgID=%s
	"""
	params = [userID, orgID]

	if start_date:
		getOrdersQuery += " AND DATE(orderTime) >= %s"
		params.append(start_date.isoformat())

	if end_date:
		getOrdersQuery += " AND DATE(orderTime) <= %s"
		params.append(end_date.isoformat())

	getOrdersQuery += " ORDER BY orderTime DESC"

	previousOrders = selectDb(query=getOrdersQuery, params=tuple(params))

	if len(previousOrders)<1:
		return render_template(
			"previous_orders.html",
			layout="activenav.html",
			orders=[],
			start=start,
			end=end
		)

	for order in previousOrders:
		#determine order status
		if date.today() >= order.get("estimatedArrival"):
			order["status"] = "Delivered"
		else: 
			order["status"] = "In Transit"
		#convert order date/time into clean strings
		uglyDateTime = order.get("orderTime")
		order.pop("orderTime")
		order["orderDate"] = uglyDateTime.strftime("%b %d, %Y")
		order["orderTime"] = uglyDateTime.strftime("%I:%M %p")
		#also clean estimated delivery date
		uglyDateTime = order.get("estimatedArrival")
		order.pop("estimatedArrival")
		order["estimatedArrival"] = uglyDateTime.strftime("%b %d, %Y")
		#add a list of products to the dictionary
		#get list of items associated with the order
		getOrderItemsQuery = """
			SELECT
				productID,
				unitPrice,
				totalPrice,
				amount
			FROM OrderItems
			WHERE orderID=%s
		"""
		orderItems = selectDb(query=getOrderItemsQuery, params=(order.get("orderID")))
		order["orderItems"] = orderItems

		#get total number of items ordered
		itemCount = 0
		for item in orderItems:
			quantity = item.get("amount")
			itemCount += quantity
		order["itemQuantity"] = itemCount

		firstProductID = order.get("orderItems")[0].get("productID")
		orderThumbnail = getProductData(firstProductID).get("thumbnail")
		order["thumbnail"] = orderThumbnail

	return render_template(
		"previous_orders.html",
		layout="activenav.html",
		orders=previousOrders,
		start=start,
		end=end
	)

@application.route("/bulkRegister")
def bulkRegister():
	if "UserID" not in session or session.get("role")=="Driver":
		return redirect(url_for("home"))
	return render_template("bulk_upload.html", layout="activenav.html")

# helper for bulk upload usernames
def make_bulk_username(first_name, last_name, email):
	base = f"{first_name}.{last_name}".lower().replace(" ", "")
	base = base.replace("'", "").replace('"', "")
	if not base or paramQueryDb("SELECT UserID FROM Users WHERE Username=%s", (base,)):
		base = email.split("@")[0].lower()
	candidate = base
	counter = 1
	while paramQueryDb("SELECT UserID FROM Users WHERE Username=%s", (candidate,)):
		candidate = f"{base}{counter}"
		counter += 1
	return candidate

# helper to add point adjustment record
def create_point_adjustment_for_driver(driver_username, org_id, points, reason):
	if not points or int(points) <= 0:
		return

	updateDb("""
		INSERT INTO PointAdjustments
		(OrganizationID, DriverUName, AdjustedByUName, AdjustmentType, AdjustmentPoints, AdjustmentReason, DateAdjusted)
		VALUES (%s, %s, %s, %s, %s, %s, %s)
	""", (
		org_id,
		driver_username,
		session.get("Username", "admin"),
		"Award",
		int(points),
		reason or "Bulk upload",
		datetime.now()
	))

def get_driver_point_history(driver_id, org_id, limit=None):
	user = paramQueryDb("SELECT Username FROM Users WHERE UserID=%s", (driver_id,))
	username = user.get("Username") if user else None

	transactions = []
	if username:
		point_adjustments = selectDb("""
			SELECT
				DateAdjusted AS event_time,
				CASE WHEN AdjustmentType='Deduct' THEN -ABS(COALESCE(AdjustmentPoints, 0))
					 ELSE ABS(COALESCE(AdjustmentPoints, 0)) END AS delta_points,
				AdjustmentType AS transaction_type,
				COALESCE(AdjustmentReason, '') AS description
			FROM PointAdjustments
			WHERE OrganizationID=%s AND DriverUName=%s
		""", (org_id, username)) or []
		for row in point_adjustments:
			transactions.append({
				"event_time": row.get("event_time"),
				"delta_points": int(row.get("delta_points") or 0),
				"transaction_type": row.get("transaction_type") or "Adjustment",
				"description": row.get("description") or "",
			})

		pending_rows = selectDb("""
			SELECT CreatedAt, TransactionType, PendingPoints, Description, Status
			FROM PendingPointTransactions
			WHERE OrganizationID=%s AND DriverUName=%s AND Status='Pending'
			ORDER BY CreatedAt DESC
		""", (org_id, username)) or []
	else:
		pending_rows = []

	order_rows = selectDb("""
		SELECT orderTime, pointTotal, orderID
		FROM Orders
		WHERE userID=%s AND orgID=%s
	""", (driver_id, org_id)) or []

	for row in order_rows:
		transactions.append({
			"event_time": row.get("orderTime"),
			"delta_points": -abs(int(row.get("pointTotal") or 0)),
			"transaction_type": "Redeemed",
			"description": f"Order #{row.get('orderID')}",
		})

	transactions.sort(key=lambda item: item.get("event_time") or datetime.min, reverse=True)

	balance_row = paramQueryDb("""
		SELECT TotalPoints
		FROM DriverOrganizations
		WHERE DriverID=%s AND OrganizationID=%s
	""", (driver_id, org_id)) or {}

	running_balance = int(balance_row.get("TotalPoints") or 0)

	for tx in transactions:
		tx["balance_after"] = running_balance
		running_balance -= int(tx.get("delta_points") or 0)
		tx["display_date"] = tx["event_time"].strftime("%b %d, %Y") if tx.get("event_time") else ""
		tx["display_time"] = tx["event_time"].strftime("%I:%M %p") if tx.get("event_time") else ""

	pending = []
	for row in pending_rows:
		created = row.get("CreatedAt")
		pending.append({
			"display_date": created.strftime("%b %d, %Y") if created else "",
			"display_time": created.strftime("%I:%M %p") if created else "",
			"transaction_type": row.get("TransactionType") or "Pending",
			"pending_points": int(row.get("PendingPoints") or 0),
			"description": row.get("Description") or "",
			"status": row.get("Status") or "Pending",
		})

	if limit:
		transactions = transactions[:limit]

	return {
		"balance": int(balance_row.get("TotalPoints") or 0),
		"transactions": transactions,
		"pending": pending,
	}

@application.route("/driver/points")
def driver_point_history():
	if "UserID" not in session or session.get("role") != "Driver":
		return redirect(url_for("home"))

	org_id = session.get("OrgID")
	if not org_id:
		flash("Select an organization before viewing point history.", "validation")
		return redirect(url_for("home"))

	point_summary = get_driver_point_history(session["UserID"], org_id)

	if request.args.get("format", "").lower() == "csv":
		rows = []
		for tx in point_summary["transactions"]:
			rows.append({
				"Date": tx.get("display_date"),
				"Time": tx.get("display_time"),
				"TransactionType": tx.get("transaction_type"),
				"PointsChange": tx.get("delta_points"),
				"BalanceAfter": tx.get("balance_after"),
				"Description": tx.get("description"),
			})
		return build_csv_response(
			"driver_point_history.csv",
			["Date", "Time", "TransactionType", "PointsChange", "BalanceAfter", "Description"],
			rows
		)

	return render_template(
		"driver_point_history.html",
		layout="activenav.html",
		point_summary=point_summary
	)

def isFileType(filename:str, extension:str):
	return filename.lower().endswith(extension.lower())

def validate_bulk_upload_line(line_parts):
	record_type = (line_parts[0] if line_parts else "").upper()

	if record_type not in {"O", "S", "D"}:
		raise ValueError("Only O, S, and D records are supported in admin bulk upload.")

	if record_type == "O":
		if len(line_parts) < 2 or not line_parts[1].strip():
			raise ValueError("Organization rows must include an organization name.")
		return

	if len(line_parts) < 5:
		raise ValueError("User rows must include organization, first name, last name, and email.")

	if not line_parts[1].strip():
		raise ValueError("Organization name is required.")

	if not line_parts[2].strip() or not line_parts[3].strip():
		raise ValueError("First and last name are required.")

	if not line_parts[4].strip() or "@" not in line_parts[4]:
		raise ValueError("A valid email address is required.")

	if record_type == "S" and len(line_parts) > 5 and line_parts[5].strip():
		raise ValueError("Sponsor rows cannot include points.")

	if len(line_parts) > 5 and line_parts[5].strip() and not line_parts[5].strip().lstrip("-").isdigit():
		raise ValueError("Points must be a whole number.")

def processSponsorBulkFile(bulkFile, orgID):
	lineNum=0
	for line in bulkFile:
		lineNum+=1
		try:
			lineString = line.decode("utf-8").strip()
			lineParts = lineString.split("|")
			#grab values from lineParts
			if len(lineParts) not in [7,5]:
				raise Exception("Formating issue. Incorrect number of arguments provided")
			userType = lineParts[0].upper()
			orgName = lineParts[1]
			firstName = lineParts[2]
			lastName = lineParts[3]
			email = lineParts[4]
			if (len(lineParts)>5):
				points = lineParts[5]
				reason = lineParts[6]
			if userType.upper() not in ["D","S"]:
				raise Exception("Invalid user type character")
			if orgName:
				raise Exception("Defining an organization for the user is not allowed")
			if not firstName:
				raise Exception("No user first name provided")
			if not lastName:
				raise Exception("No user last name provided")
			if not email:
				raise Exception("No user email provided")
			if points and not reason:
				raise Exception("Points were provided without also providing a reason for the points")
			if points and userType.upper()=="S":
				flash(f"Points were not added for sponsor account (line: {lineNum})", category="bulkError")
		
			#logic for driver user
			if userType=="D":
				userType = "Driver"
				#determine if we are updating driver data or defining a new driver
				DriverExistInOrgQuery = """
					SELECT DriverID, TotalPoints
					FROM DriverOrganizations
					LEFT JOIN Users on DriverID=UserID
					WHERE OrganizationID=%s
						AND Users.Email=%s
				"""
				queryResults = paramQueryDb(DriverExistInOrgQuery, params=(orgID, email))
				driverID = queryResults.get("DriverID") if queryResults else None
				previousPoints = queryResults.get("TotalPoints") if queryResults else None
				if driverID and points:
					#change driver points
					updateDriverPointsQuery = """
						UPDATE DriverOrganizations
						SET
							TotalPoints=%s
						WHERE 
							DriverID=%s
							AND OrganizationID=%s
					"""
					updateDb(updateDriverPointsQuery, params=(points, driverID, orgID))
					#get driver's username from usertable
					getDriverUsernameQuery = """
						SELECT Username
						FROM Users
						WHERE UserID=%s
					"""
					driverUsername = paramQueryDb(getDriverUsernameQuery, params=(driverID)).get("Username")
					#log the point change
					adjustmentType = "Award" if not previousPoints or int(previousPoints)<=int(points) else "Deduct"
					pointDiff = int(points)-int(previousPoints) if adjustmentType=="Award" else int(previousPoints)-int(points)
					pointAdjustmentLogQuery = """
						INSERT INTO PointAdjustments
							(OrganizationID, DriverUName, AdjustedByUName, AdjustmentType, AdjustmentPoints, AdjustmentReason, DateAdjusted)
						VALUES
							(%s,%s,%s,%s,%s,%s,%s)
					"""
					updateDb(pointAdjustmentLogQuery, params=(orgID, driverUsername, session.get("Username"), adjustmentType, pointDiff, reason, datetime.now()))
				elif not driverID:
					#create user
					username = firstName+lastName
					createUserQuery = """
						INSERT INTO Users
							(Email, Username, Password_hash, UserType, Name)
						VALUES
							(%s,%s,%s,%s,%s)
					"""
					conn = getDbConnection()
					cursor = conn.cursor()
					cursor.execute(createUserQuery, args=(email, username, 
						generate_password_hash("TempPass123!", method="pbkdf2:sha256"),
						userType, firstName+" "+lastName))
					conn.commit()
					userID = cursor.lastrowid
					print(userID)
					#insert into Drivers
					createDriverQuery = """
						INSERT INTO Drivers
							(DriverID)
						VALUES
							(%s)
					"""
					updateDb(createDriverQuery, params=(userID))
					#insert into DriverOrganizations
					insertDriverOrgQuery = """
						INSERT INTO DriverOrganizations
							(DriverID, OrganizationID, Status,
							TotalPoints)
						VALUES
							(%s,%s,%s,%s)
					"""
					updateDb(insertDriverOrgQuery, params=(userID, orgID, "Active", points if points else 0))
					#insert into PointAdjustments
					insertPointAdjustmentsQuery = """
						INSERT INTO PointAdjustments
							(OrganizationID, DriverUName, AdjustedByUName, AdjustmentType, AdjustmentPoints, AdjustmentReason, DateAdjusted)
						VALUES
							(%s,%s,%s,%s,%s,%s,%s,%s)
					"""
					updateDb(insertPointAdjustmentsQuery, params=(orgID, username, session.get("Username"), "Award", points if points else 0, reason, datetime.now()))
			#logic for sponsor user
			else :
				userType = "Sponsor"
				#determine if we are updating sponsor data or defining a new sponsor
				SponsorExistsInOrgQuery = """
					SELECT SponsorID
					FROM Users
					LEFT JOIN Sponsors on UserID=SponsorID
					WHERE 
						OrganizationID=%s
						AND Email=%s
				"""
				queryResults = paramQueryDb(SponsorExistsInOrgQuery, params=(orgID, email))
				sponsorID = queryResults.get("SponsorID") if queryResults else None
				if sponsorID:
					#update sponsor name in Users table
					updateSponsorDataQuery = """
						UPDATE Users
						SET Name=%s
						WHERE UserID=%s
					"""
					updateDb(updateSponsorDataQuery, params=(firstName+' '+lastName, sponsorID))
				elif not sponsorID:
					#create sponsor
					username = firstName+lastName
					createUserQuery = """
						INSERT INTO Users
							(Email, Username, Password_hash, UserType, Name)
						VALUES
							(%s,%s,%s,%s,%s)
					"""
					conn = getDbConnection()
					cursor = conn.cursor()
					cursor.execute(createUserQuery, args=(email, username, 
						generate_password_hash("TempPass123!", method="pbkdf2:sha256"),
						userType, firstName+" "+lastName))
					conn.commit()
					userID = cursor.lastrowid
					#insert into Drivers
					createSponsorQuery = """
						INSERT INTO Sponsors
							(SponsorID, OrganizationID)
						VALUES
							(%s,%s)
					"""
					updateDb(createSponsorQuery, params=(userID, orgID))
		except Exception as e:
			errorMessage = f"{str(e)} (line: {lineNum})"
			flash(errorMessage, "bulkError")
			continue
	return

def process_admin_bulk_lines(lines):
	results = []
	success_count = 0
	error_count = 0

	for line_num, raw_line in enumerate(lines, start=1):
		line_string = raw_line.decode("utf-8").strip() if isinstance(raw_line, bytes) else str(raw_line).strip()

		if not line_string:
			continue

		try:
			line_parts = [part.strip() for part in line_string.split("|")]
			validate_bulk_upload_line(line_parts)

			record_type = line_parts[0].upper()

			if record_type == "O":
				org_name = line_parts[1]
				org = paramQueryDb(
					"SELECT OrganizationID FROM Organizations WHERE Name=%s",
					(org_name,)
				)
				if not org:
					updateDb(
						"INSERT INTO Organizations (Name, TimeCreated) VALUES (%s, %s)",
						(org_name, datetime.now())
					)
					results.append({"line": line_num, "status": "success", "message": f"Organization created: {org_name}"})
				else:
					results.append({"line": line_num, "status": "success", "message": f"Organization ready: {org_name}"})
				success_count += 1
				continue

			org_name = line_parts[1]
			first_name = line_parts[2]
			last_name = line_parts[3]
			email = line_parts[4]
			points = int(line_parts[5]) if len(line_parts) > 5 and line_parts[5].strip() else 0
			reason = line_parts[6] if len(line_parts) > 6 else "Bulk upload"

			org = paramQueryDb(
				"SELECT OrganizationID FROM Organizations WHERE Name=%s",
				(org_name,)
			)
			if not org:
				raise ValueError(f"Organization does not exist: {org_name}")

			existing_user = paramQueryDb(
				"SELECT UserID, Username, UserType FROM Users WHERE Email=%s",
				(email,)
			)

			if existing_user and existing_user["UserType"] == "Admin":
				raise ValueError("Admin users cannot be created or modified through bulk upload.")

			if record_type == "S":
				full_name = f"{first_name} {last_name}"

				if existing_user:
					if existing_user["UserType"] != "Sponsor":
						raise ValueError("Existing email belongs to a non-sponsor user.")
					updateDb(
						"UPDATE Users SET Name=%s WHERE UserID=%s",
						(full_name, existing_user["UserID"])
					)
					results.append({"line": line_num, "status": "success", "message": f"Sponsor updated: {email}"})
				else:
					username = make_bulk_username(first_name, last_name, email)
					temp_password_hash = generate_password_hash("TempPass123!", method="pbkdf2:sha256")

					updateDb("""
						INSERT INTO Users (Email, Username, Password_hash, TimeCreated, UserType, Name)
						VALUES (%s, %s, %s, %s, %s, %s)
					""", (email, username, temp_password_hash, datetime.now(), "Sponsor", full_name))

					new_user = paramQueryDb(
						"SELECT UserID FROM Users WHERE Email=%s",
						(email,)
					)

					updateDb("""
						INSERT INTO Sponsors (SponsorID, OrganizationID)
						VALUES (%s, %s)
					""", (new_user["UserID"], org["OrganizationID"]))

					results.append({"line": line_num, "status": "success", "message": f"Sponsor created: {email}"})

				success_count += 1
				continue

			if record_type == "D":
				full_name = f"{first_name} {last_name}"

				if existing_user:
					if existing_user["UserType"] != "Driver":
						raise ValueError("Existing email belongs to a non-driver user.")

					updateDb(
						"UPDATE Users SET Name=%s WHERE UserID=%s",
						(full_name, existing_user["UserID"])
					)

					existing_driver_org = paramQueryDb("""
						SELECT DriverID
						FROM DriverOrganizations
						WHERE DriverID=%s AND OrganizationID=%s
					""", (existing_user["UserID"], org["OrganizationID"]))

					if not existing_driver_org:
						updateDb("""
							INSERT INTO DriverOrganizations (DriverID, OrganizationID, Status, TotalPoints)
							VALUES (%s, %s, %s, %s)
						""", (existing_user["UserID"], org["OrganizationID"], "Active", 0))

					existing_app = paramQueryDb("""
						SELECT ApplicationID
						FROM OrganizationApplications
						WHERE OrganizationID=%s AND DriverUName=%s
					""", (org["OrganizationID"], existing_user["Username"]))

					if existing_app:
						updateDb("""
							UPDATE OrganizationApplications
							SET ApplicationStatus=%s, ReviewedByUName=%s, ReviewReason=%s
							WHERE ApplicationID=%s
						""", ("Accepted", "bulk_admin", "Auto-accepted by bulk upload", existing_app["ApplicationID"]))
					else:
						updateDb("""
							INSERT INTO OrganizationApplications
							(OrganizationID, DriverUName, DateApplied, ReviewedByUName, ApplicationStatus, ReviewReason)
							VALUES (%s, %s, %s, %s, %s, %s)
						""", (
							org["OrganizationID"],
							existing_user["Username"],
							datetime.now(),
							"bulk_admin",
							"Accepted",
							"Auto-accepted by bulk upload"
						))

					create_point_adjustment_for_driver(existing_user["Username"], org["OrganizationID"], points, reason)
					results.append({"line": line_num, "status": "success", "message": f"Driver updated: {email}"})
					success_count += 1
					continue

				username = make_bulk_username(first_name, last_name, email)
				temp_password_hash = generate_password_hash("TempPass123!", method="pbkdf2:sha256")

				updateDb("""
					INSERT INTO Users (Email, Username, Password_hash, TimeCreated, UserType, Name)
					VALUES (%s, %s, %s, %s, %s, %s)
				""", (email, username, temp_password_hash, datetime.now(), "Driver", full_name))

				new_user = paramQueryDb(
					"SELECT UserID, Username FROM Users WHERE Email=%s",
					(email,)
				)

				try:
					updateDb(
						"INSERT INTO DriverOrganizations (DriverID, OrganizationID) VALUES (%s, %s)",
						(new_user["UserID"], org["OrganizationID"])
					)
				except Exception as e:
					print("Drivers insert skipped:", e)

				try:
					updateDb("""
						INSERT INTO DriverOrganizations (DriverID, OrganizationID, Status, TotalPoints)
						VALUES (%s, %s, %s, %s)
					""", (new_user["UserID"], org["OrganizationID"], "Active", 0))
				except Exception as e:
					print("DriverOrganizations insert skipped:", e)

				updateDb("""
					INSERT INTO OrganizationApplications
					(OrganizationID, DriverUName, DateApplied, ReviewedByUName, ApplicationStatus, ReviewReason)
					VALUES (%s, %s, %s, %s, %s, %s)
				""", (
					org["OrganizationID"],
					new_user["Username"],
					datetime.now(),
					"bulk_admin",
					"Accepted",
					"Auto-accepted by bulk upload"
				))

				create_point_adjustment_for_driver(new_user["Username"], org["OrganizationID"], points, reason)
				results.append({"line": line_num, "status": "success", "message": f"Driver created: {email}"})
				success_count += 1
				continue

		except Exception as e:
			results.append({"line": line_num, "status": "error", "message": str(e)})
			error_count += 1

	return {
		"results": results,
		"success_count": success_count,
		"error_count": error_count,
	}

@application.route("/users/bulk/sponsor", methods=["POST"])
def sponsorBulkUpload():
	if "UserID" not in session or session.get("role")!="Sponsor":
		return redirect(url_for("home"))
	
	#ensure that the file we are looking for was sent in the request
	if 'bulk-update-file' not in request.files:
		flash("file not found")
		return redirect(url_for("bulkRegister"))

	uploadFile = request.files['bulk-update-file']

	if uploadFile.filename == "":
		flash("No file selected")
		return redirect(url_for("bulkRegister"))
	
	#ensure user uploaded a .txt file
	if not isFileType(uploadFile.filename, ".txt"):
		flash("wrong file type")
		return redirect(url_for("bulkRegister"))

	#process the file line by line
	processSponsorBulkFile(uploadFile, session.get("OrgID"))

	return redirect(url_for("bulkRegister"))

@application.route("/users/bulk/admin", methods=["POST"])
def adminBulkUpload():
	if "UserID" not in session or session.get("role") != "Admin":
		return redirect(url_for("home"))

	if 'bulk-update-file' not in request.files:
		flash("No file uploaded.", "validation")
		return redirect(url_for("bulkRegister"))

	uploadFile = request.files['bulk-update-file']

	if uploadFile.filename == "":
		flash("No file selected.", "validation")
		return redirect(url_for("bulkRegister"))

	if not isFileType(uploadFile.filename, ".txt"):
		flash("Please upload a .txt file.", "validation")
		return redirect(url_for("bulkRegister"))

	result = process_admin_bulk_lines(uploadFile)

	for entry in result["results"]:
		category = "success" if entry["status"] == "success" else "bulkError"
		flash(f"Line {entry['line']}: {entry['message']}", category)

	flash(
		f"Bulk upload finished. Success: {result['success_count']}, Errors: {result['error_count']}.",
		"success"
	)
	return redirect(url_for("bulkRegister"))

@application.route("/product/inCart/<int:productID>")
def inCart(productID):
	if session.get("role")!="Driver":
		return jsonify(False)
	
	#check cart table
	try:
		inCartTableQuery = """
			SELECT 1
			FROM Cart
			WHERE
				userID=%s
				AND orgID=%s
				AND productID=%s
		"""
		queryResults = paramQueryDb(query=inCartTableQuery, params=(session.get("UserID"),session.get("OrgID"),productID))
		if queryResults:
			return jsonify(True)
		return jsonify(False)
	except Exception as e:
		print(e)
		return jsonify(False)

@application.route("/order/<int:orderID>/details")
def orderDetails(orderID):
	if "UserID" not in session or "OrgID" not in session or session.get("role")!="Driver":
		return redirect(url_for("home"))
	
	getOrderQuery = """
		SELECT *
		FROM Orders
		WHERE orderID=%s
	"""
	getOrderItemsQuery = """
		SELECT *
		FROM OrderItems
		WHERE orderID=%s
	"""
	try:
		orderDbDetails = paramQueryDb(query=getOrderQuery, params=(orderID))
		orderItems = selectDb(query=getOrderItemsQuery, params=(orderID))
	except Exception as e:
		print(e)
		return redirect(url_for("previousOrders"))
	
	#don't show order details if the order details don't match the session details
	if orderDbDetails.get("userID")!=session.get("UserID") or orderDbDetails.get("orgID")!=session.get("OrgID"):
		return redirect(url_for("previousOrders"))

	print(orderDbDetails)
	print(orderItems)

	return redirect(url_for("previousOrders"))

"""
This lets us test locally. Should not execute in AWS
"""
if __name__ == "__main__":

	application.run()