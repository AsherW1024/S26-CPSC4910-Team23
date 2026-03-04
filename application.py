from flask import Flask, render_template, redirect, url_for
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
	return redirect(url_for("home"))

@application.route("/register")
def register():
	return render_template("register.html")

@application.route("/register", methods=["POST"])
def registerUser():
	return redirect(url_for("login"))