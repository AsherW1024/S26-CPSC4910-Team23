from flask import *
import pymysql
from config import db_config

application = Flask(__name__)



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



"""
This is the about page. Right now it serves as the landing page. Later this will
need to be changed to have a different route. '@application.route("/about/")'
for example.
"""
@application.route("/")
def about():
	#query db to find out how many accounts are in accounts table
	accountCount = queryDb("select count(*), count(account_id) from accounts")
	accountCount = accountCount['count(*)']

	return render_template("about.html", accountCount=accountCount)

if __name__ == "__main__":
	application.run()