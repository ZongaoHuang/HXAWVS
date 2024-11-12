import sqlite3
from datetime import datetime

conn = sqlite3.connect('db.sqlite3')
c = conn.cursor()
print("open database")


c.execute("DELETE FROM table_name")
c.execute("UPDATE sqlite_sequence SET seq = 0 WHERE name = ‘TableName’")
conn.commit()
conn.close()