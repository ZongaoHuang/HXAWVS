import sqlite3
conn = sqlite3.connect('db.sqlite3')
c = conn.cursor()
print("open database")
c.execute("DELETE * from dirscan_directoryscan")
conn.commit()

print "Total number of rows deleted :", conn.total_changes

conn.close()