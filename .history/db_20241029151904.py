import sqlite3


conn = sqlite3.connect('db.sqlite3')
c = conn.cursor()
print("open database")

# 删除表中的所有数据
c.execute("DELETE FROM webscan_backend_portscan")

# 重置自增主键的计数
c.execute("UPDATE sqlite_sequence SET seq = 0 WHERE name = 'table_name'")

conn.commit()
conn.close()