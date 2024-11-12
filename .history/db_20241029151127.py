import sqlite3
from datetime import datetime

conn = sqlite3.connect('db.sqlite3')
c = conn.cursor()
print("open database")

DELETE FROM table_name;

conn.commit()
conn.close()