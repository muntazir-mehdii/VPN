import sqlite3
import hashlib

conn = sqlite3.connect('vpn_data.db')
c = conn.cursor()
c.execute("SELECT * FROM users")
users = c.fetchall()
print("Users in DB:", users)

admin_pw = "admin"
pw_hash = hashlib.sha256(admin_pw.encode()).hexdigest()
print(f"Calculated Hash for 'admin': {pw_hash}")

for u in users:
    if u[1] == 'admin':
        print(f"DB Hash for 'admin': {u[2]}")
        print(f"Match? {u[2] == pw_hash}")
        
conn.close()
