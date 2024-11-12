import sqlite3
conn = sqlite3.connect('db.sqlite3')
c = conn.cursor()
print("open database"
conn.close()