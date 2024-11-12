import sqlite3
from datetime import datetime

conn = sqlite3.connect('db.sqlite3')
c = conn.cursor()
print("open database")

# 删除表中的所有数据
c.execute("DELETE FROM table_name")

# 重置自增主键的计数
c.execute("UPDATE sqlite_sequence SET seq = 0 WHERE name = 'table_name'")

conn.commit()
conn.close()