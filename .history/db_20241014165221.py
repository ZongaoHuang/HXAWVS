import sqlite3
conn = sqlite3.connect('db.sqlite3')
c = conn.cursor()
print("open database")
c.execute("INSERT INTO dirscan_directoryscan (target, ) VALUES (?, ?)", (value1, value2))
conn.commit()
conn.close()