import sqlite3
from datetime import datetime

conn = sqlite3.connect('db.sqlite3')
c = conn.cursor()
print("open database")

# 获取当前日期和时间
now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

c.execute(DELETE FROM table_name")
conn.commit()
conn.close()