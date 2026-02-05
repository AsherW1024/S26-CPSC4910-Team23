from flask import Flask, render_template, redirect, url_for, request
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
import pymysql
from config import db_config
import os

application = Flask(__name__)

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
	#query db to find out how many accounts are in accounts table
	accountCount = queryDb("select count(*), count(account_id) from accounts")
	accountCount = accountCount['count(*)']

	return render_template("about.html", accountCount=accountCount)

@application.route("/login")
def login():
	return render_template("login.html")

@application.route("/login", methods=["POST"])
def loginUser():

	identifier = request.form.get("identifier")
	exists = paramQueryDb("select UserID, Password_hash from Users where Email = %s or Username = %s", (identifier, identifier))

	if not exists:
		return redirect(url_for("login"))

	password = request.form.get("password")
	hashPassword = exists["Password_hash"]

	if not exists or not check_password_hash(hashPassword, password):
		return redirect(url_for("login"))
		
	return redirect(url_for("home"))

@application.route("/register")
def register():
	return render_template("register.html")

@application.route("/register", methods=["POST"])
def registerUser():
	email = request.form.get("email")

	exists = paramQueryDb("select UserID from Users where Email=%s", (email,))

	if exists:
		return redirect(url_for("login"))

	name = request.form.get("name")
	username = request.form.get("username")
	password = request.form.get("password")
	if not username or not password:
		return redirect(url_for("register"))
	hashPassword = generate_password_hash(password)
	timeCreated = datetime.now()

	insertDb(
		"""INSERT INTO Users (Email, Name, Username, Password_hash, TimeCreated)
		VALUES (%s, %s, %s, %s, %s)""", (email, name, username, hashPassword, timeCreated))

	return redirect(url_for("login"))