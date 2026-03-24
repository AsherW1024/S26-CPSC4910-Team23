from flask import Flask, render_template, redirect, url_for, request, session, flash, jsonify, Response
from functools import wraps
from datetime import datetime, timedelta
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

# Define security tables and seed default permissions on startup
init_security_tables()
seed_default_role_permissions()

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
        LEFT JOIN Drivers d ON u.UserID = d.DriverID
        LEFT JOIN Organizations o ON o.OrganizationID = COALESCE(s.OrganizationID, d.OrganizationID)
        WHERE u.UserID = %s
    """, (user_id,))
    return row.get("OrganizationName") if row else None

def log_password_event(event_type: str, actor_user_id=None, target_user_id=None):
    actor_ip = get_request_ip()
    event_time = datetime.now()

    org_name = None
    for uid in (target_user_id, actor_user_id):
        if uid and not org_name:
            org_name = get_org_name_for_user(uid)

    org_id = None
    if org_name:
        org = paramQueryDb("SELECT OrganizationID FROM Organizations WHERE Name=%s", (org_name,))
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
	if "UserID" in session and session["role"] != "Admin":
		org = selectDb("""SELECT o.Name, o.OrganizationID
							FROM Users u 
							LEFT JOIN Sponsors s ON u.UserID = s.SponsorID 
							LEFT JOIN Drivers d ON u.UserID = d.DriverID
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

def get_request_ip():
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.remote_addr

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
    row = paramQueryDb("SELECT FailedCount FROM LoginAttemptTracker WHERE ScopeType=%s AND ScopeValue=%s", (scope_type, scope_value))
    failed_count = (row.get('FailedCount') if row else 0) + 1
    locked_until = datetime.utcnow() + timedelta(minutes=LOGIN_LOCKOUT_MINUTES) if failed_count >= LOGIN_MAX_ATTEMPTS else None
    updateDb("""
        INSERT INTO LoginAttemptTracker (ScopeType, ScopeValue, FailedCount, LockedUntil, LastFailedAt)
        VALUES (%s, %s, %s, %s, %s)
        ON DUPLICATE KEY UPDATE
            FailedCount=%s,
            LockedUntil=%s,
            LastFailedAt=%s
    """, (scope_type, scope_value, failed_count, locked_until, datetime.utcnow(), failed_count, locked_until, datetime.utcnow()))
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
		LEFT JOIN Drivers d ON u.UserID = d.DriverID
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
			JOIN Drivers d ON u.UserID = d.DriverID
			WHERE u.UserType = "Driver"
			  AND (d.OrganizationID IS NULL OR d.OrganizationID = 0)
			  AND (u.Name LIKE %s OR u.Email LIKE %s OR u.Username LIKE %s)
		""", (like, like, like))

		drivers = selectDb("""
			SELECT u.UserID, u.Name, u.Email, u.Username
			FROM Users u
			JOIN Drivers d ON u.UserID = d.DriverID
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
			JOIN Drivers d ON u.UserID = d.DriverID
			WHERE u.UserType = "Driver"
			  AND (d.OrganizationID IS NULL OR d.OrganizationID = 0)
		""", ())

		drivers = selectDb("""
			SELECT u.UserID, u.Name, u.Email, u.Username
			FROM Users u
			JOIN Drivers d ON u.UserID = d.DriverID
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
		JOIN Drivers d ON u.UserID = d.DriverID
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
		UPDATE Drivers
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
			LEFT JOIN Drivers td ON u.UserID = td.DriverID
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
			LEFT JOIN Drivers td ON u.UserID = td.DriverID
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
			ORDER BY a.DateApplied DESC
		"""
		csv_headers = ["DateApplied", "Name", "DriverUName", "ReviewedByUName", "ApplicationStatus", "ReviewReason"]

	else:
		count_query = f"""
			SELECT COUNT(*) AS totalRows
			FROM Logins l
			LEFT JOIN Users lu ON (lu.Email = l.LoginUser OR lu.Username = l.LoginUser)
			LEFT JOIN Sponsors ls ON lu.UserID = ls.SponsorID
			LEFT JOIN Drivers ld ON lu.UserID = ld.DriverID
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
			LEFT JOIN Drivers ld ON lu.UserID = ld.DriverID
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
		if session.get("Organization") != None and session.get("role") == "Admin":
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
	return render_template("bugReport.html", layout="activenav.html", prevPage=prevPage)

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

	profile = decrypt_fields(profile, ["PhoneNumber"])

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

	user = decrypt_fields(user, ["PhoneNumber"])

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

	user = decrypt_fields(user, ["PhoneNumber"])

	if PhoneNumber != (user.get("PhoneNumber") or ""):
		update_fields.append("PhoneNumber=%s")
		update_vals.append(encrypt_value(PhoneNumber) if PhoneNumber else None)

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
		log_password_event("change", actor_user_id=session["UserID"], target_user_id=session["UserID"])

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
							currentPref=prefs[0]["PrefCommMethod"], hasPhoneNum=hasPhoneNum, essentialNotifs=prefs[0]["EssentialNotifsOnly"], ) 

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
	
	return render_template("orgList.html", layout="activenav.html", orgs=orgs, q=q, page=page, pageNum=range(1, numPages + 1), pageRows=rowsPerPage)

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
        JOIN Drivers d ON u.UserID = d.DriverID
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
        JOIN Drivers d ON u.UserID = d.DriverID
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
		updateDb("""UPDATE Drivers SET OrganizationID = %s WHERE DriverID = %s""", (None, UserID,))
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

		return render_template("cart.html", layout="activenav.html", cartProductData=cartProductData)
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
	if cartItems==[]:
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
		FROM Drivers
		WHERE 
			DriverID=%s
			AND OrganizationID=%s
	"""
	return paramQueryDb(query=getDriverPointsQuery, params=(userID, orgID)).get("TotalPoints")

def adjustDriverPoints(driverID, orgID, newPointTotal):
	adjustDriverPointsQuery = """
		UPDATE Drivers
		SET TotalPoints=%s
		WHERE
			DriverID=%s
			AND OrganizationID=%s
	"""
	updateDb(query=adjustDriverPointsQuery, params=(newPointTotal, driverID, orgID))

@application.route("/cart/checkout")
def checkout():
	if "UserID" not in session:
		return redirect(url_for("home"))
	try:
		userID = session.get("UserID")
		orgID = session.get("OrgID")

		cartTotal = getCartTotal(userID, orgID)

		driverPointTotal = getDriverPoints()

		#don't let user get past cart screen unless they have enough points
		if driverPointTotal < cartTotal:
			raise Exception("Driver does not have enough points to complete the order")

	#go back to cart screen if an error occurs
	except Exception as e:
		print(e)
		return redirect(url_for("cart"))
	#if user has enough points for the order, continue to checkout screen
	return render_template("checkout.html", layout="activenav.html")

def getCartData(userID, orgID):
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

	return cartProductData

@application.route("/orders/confirm", methods=["POST"])
def orderConfirmation():
	if "UserID" not in session:
		return redirect(url_for("home"))
	
	#grab cart data
	userID = session.get("UserID")
	orgID = session.get("OrgID")
	cartData = getCartData(userID=userID, orgID=orgID)

	#grab address data from form
	addressDict = {}
	addressDict["address"] = request.form.get("address")
	addressDict["city"] = request.form.get("city")
	addressDict["state"] = request.form.get("state")

	#calculate order total
	orderTotal = getCartTotal(userID, orgID)

	#send user to confirmation screen to confirm before the pull the trigger on their order
	return render_template("confirm_order.html", layout="activenav.html", cart=cartData, address=addressDict, total=orderTotal)

@application.route("/orders", methods=["POST"])
def makeOrder():
	if "UserID" not in session:
		return redirect(url_for("home"))
	
	try:
		userID = session.get("UserID")
		orgID = session.get("OrgID")

		cartTotal = getCartTotal(userID, orgID)
		driverPointTotal = getDriverPoints()
		newDriverPointTotal = driverPointTotal-cartTotal

		#lower driver's point total
		adjustDriverPoints(userID, orgID, newDriverPointTotal)

		#insert info into Orders table
		address = encrypt_value(request.form.get("address"))
		city = encrypt_value(request.form.get("city"))
		state = encrypt_value(request.form.get("state"))

		#insert into Order table with a cursor to keep track of that entry's orderID
		connection = getDbConnection()
		cursor = connection.cursor()
		insertOrderQuery = """
			INSERT INTO Orders
				(userID, orgID, pointTotal, deliveryAddress, deliveryCity, deliveryState, orderTime, estimatedArrival)
			VALUES 
				(%s,%s,%s,%s,%s,%s,%s,%s + INTERVAL 1 WEEK)
		"""
		cursor.execute(query=insertOrderQuery, args=(userID,orgID,cartTotal,address,city,state,datetime.now(),datetime.now()))
		connection.commit()
		orderID = cursor.lastrowid
		cursor.close()

		#insert list of items into OrderItems table
		cartItems = getCartData(userID, orgID)
		insertOrderItemQuery = """
			INSERT INTO OrderItems
				(orderID, productID, unitPrice, totalPrice, amount)
			VALUES
				(%s,%s,%s,%s,%s)
		"""
		for item in cartItems:
			productID = item.get("id")
			unitPrice = item.get("price")
			amount = item.get("quantity")
			totalPrice = unitPrice*amount
			updateDb(insertOrderItemQuery, params=(orderID,productID,unitPrice,totalPrice,amount))

		#delete all items from user's cart
		deleteCartItemsQuery = """
			DELETE FROM Cart
			WHERE
				userID=%s
				AND orgID=%s
		"""
		updateDb(query=deleteCartItemsQuery, params=(userID,orgID))


	except Exception as e:
		print(e)
		return redirect(url_for("checkout"))

	return redirect(url_for("cart"))

@application.route("/orders")
def previousOrders():
	if "UserID" not in session or session.get("role") != "Driver":
		return redirect(url_for("home"))
	userID = session.get("UserID")
	orgID = session.get("OrgID")
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
		ORDER BY orderTime DESC
	"""
	previousOrders = selectDb(query=getOrdersQuery, params=(userID,orgID))

	if len(previousOrders)<1:
		return render_template("previous_orders.html", layout="activenav.html", orders=[])

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

	return render_template("previous_orders.html", layout="activenav.html", orders=previousOrders)

"""
This lets us test locally. Should not execute in AWS
"""
if __name__ == "__main__":

	application.run()