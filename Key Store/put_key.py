import MySQLdb

password="qwerty"
db=MySQLdb.connect(host="localhost",port=3306,user="root",passwd=password)
cur=db.cursor()

def put(node,key):
	cur.execute("USE NODE_KEYS")
	cur.execute("INSERT INTO KEY_STORE(ID,NODE,KEY_VALUE) VALUES(NULL,%s,%s)",(node,key))
	db.commit()

put(str(sys.argv[1]),str(sys.argv[2]))
