import json
import os
import mysql.connector

# Default to the intentionally weak lab credentials, but allow overrides so the
# helper does not duplicate the same values in multiple places.
MYSQL_HOST = os.environ.get("MYSQL_HOST", "127.0.0.1")
MYSQL_PORT = int(os.environ.get("MYSQL_PORT", "23306"))
MYSQL_USER = os.environ.get("MYSQL_USER", "kamailio")
MYSQL_PASSWORD = os.environ.get("MYSQL_PASSWORD", "kamailiorw")
MYSQL_DATABASE = os.environ.get("MYSQL_DATABASE", "useragents")

mydb = mysql.connector.connect(
    host=MYSQL_HOST,
    port=MYSQL_PORT,
    user=MYSQL_USER,
    password=MYSQL_PASSWORD,
    database=MYSQL_DATABASE,
)

mycursor = mydb.cursor()
mycursor.execute("select useragent,count(useragent) as count from useragents group by useragent")
myresult = mycursor.fetchall()
out = list()
for res in myresult:
    out.append({"useragent":res[0], "count": res[1]})
print(json.dumps(out))
