import sqlite3


conn = sqlite3.connect('db.sqlite3')
c = conn.cursor()
print("open database")

# 删除表中的所有数据
c.execute("DELETE FROM webscan_backend_infoleak")
c.execute("DELETE FROM webscan_backend_fingerprint")
c.execute("DELETE FROM webscan_backend_infoleak")

# 重置自增主键的计数
c.execute("UPDATE sqlite_sequence SET seq = 0 WHERE name = 'webscan_backend_infoleak'")

conn.commit()
conn.close()