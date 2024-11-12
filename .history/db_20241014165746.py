import sqlite3
from datetime import datetime

conn = sqlite3.connect('db.sqlite3')
c = conn.cursor()
print("open database")

# 获取当前日期和时间
now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

c.execute("INSERT INTO dirscan_directoryscan (target, user_id, scan_time, status) VALUES (?, ?, ?, ?)", ('s', 4, now, 'process'))
conn.commit()
conn.close()