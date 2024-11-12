import sqlite3
from datetime import datetime

conn = sqlite3.connect('db.sqlite3')
c = conn.cursor()
print("open database")


c.execute("DELETE FROM table_name")
c.execute
conn.commit()
conn.close()