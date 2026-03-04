from flask import Flask, render_template, redirect, url_for
import pymysql
from config import db_config
import os

application = Flask(__name__)
application.secret_key = os.environ.get("SECRET_KEY", "dev-only-change-me")  # Replace with your own secret key for production (so that admins do not randomly lose access to their accounts)

#application.secret_key = os.urandom(24)  # Use a secure random key in production

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



@application.route("/")
def welcome():
	return render_template("welcome.html")

@application.route("/home")
def home():
	return render_template("home.html")

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

@application.route("/login")
def login():
	return render_template("login.html")

@application.route("/login", methods=["POST"])
def loginUser():
	return redirect(url_for("home"))

@application.route("/register")
def register():
	return render_template("register.html")

@application.route("/register", methods=["POST"])
def registerUser():
	return redirect(url_for("login"))
