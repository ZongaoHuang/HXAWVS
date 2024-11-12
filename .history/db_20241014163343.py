import sqlite3
conn = sqlite3.connect('db.sqlite3')
c = conn.cursor()
print("open database")
c.execute("DELETE * from dirscan_directoryscan")
conn.commit()
conn.close()