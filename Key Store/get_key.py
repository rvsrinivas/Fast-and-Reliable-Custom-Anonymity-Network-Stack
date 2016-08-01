import MySQLdb

password="qwerty"
db=MySQLdb.connect(host="localhost",port=3306,user="root",passwd=password)
cur=db.cursor()

def get(node):
	cur.execute("USE NODE_KEYS")
	cur.execute("SELECT KEY_VALUE FROM KEY_STORE WHERE NODE=%s",(node))
	for item in cur.fetchall():
		return str(item[0])

print get(sys.argv[1])
