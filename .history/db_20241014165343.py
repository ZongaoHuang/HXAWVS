import sqlite3
conn = sqlite3.connect('db.sqlite3')
c = conn.cursor()
print("open database")
c.execute("INSERT INTO dirscan_directoryscan (target, userid) VALUES (?, ?)", ('s', 4))
conn.commit()
conn.close()