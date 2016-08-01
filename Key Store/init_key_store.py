import MySQLdb

password="qwerty"
db=MySQLdb.connect(host="localhost",port=3306,user="root",passwd=password)
cur=db.cursor()

def init_database():
	try: 
		cur.execute("CREATE DATABASE NODE_KEYS")
	except:
		a=1
def init_table():
	cur.execute("USE NODE_KEYS")
	try:
		cur.execute("CREATE TABLE KEY_STORE(ID INT NOT NULL PRIMARY KEY AUTO_INCREMENT,NODE VARCHAR(1),KEY_VALUE VARCHAR(100))")
	except:
		a=1


init_database()
init_table()
