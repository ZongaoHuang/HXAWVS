import sqlite3


conn = sqlite3.connect('db.sqlite3')
c = conn.cursor()
print("open database")

# 删除表中的所有数据
c.execute("DELETE FROM webscan_backend_infoleak")
c.execute("DELETE FROM webscan_backend_fingerprint")
c.execute("DELETE FROM webscan_backend_portscan")
c.execute("DELETE FROM dirscan_directoryscan")
c.execute("DELETE FROM vulnscan_middleware_vuln")

# 重置自增主键的计数
c.execute("UPDATE sqlite_sequence SET seq = 0 WHERE name = 'webscan_backend_infoleak'")
c.execute("UPDATE sqlite_sequence SET seq = 0 WHERE name = 'webscan_backend_fingerprint'")
c.execute("UPDATE sqlite_sequence SET seq = 0 WHERE name = 'webscan_backend_portscan'")
c.execute("UPDATE sqlite_sequence SET seq = 0 WHERE name = 'dirscan_directoryscan'")
c.execute("UPDATE sqlite_sequence SET seq = 0 WHERE name = 'vulnscan_middleware_vuln'")
# c.execute("DELETE FROM dirscan_directoryscan WHERE id >= 14")
# c.execute("delete from django_migrations where app='dirscan'")
conn.commit()

conn.close()