import sqlite3
import hashlib
import os
from datetime import datetime

DB_PATH = "vpn_data.db"

def init_db():
    """Initialize the database with tables"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    # Users Table
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT DEFAULT 'user'
    )''')
    
    # Threat Logs Table
    c.execute('''CREATE TABLE IF NOT EXISTS threats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        threat_type TEXT,
        source_ip TEXT,
        severity TEXT,
        action TEXT
    )''')
    
    # Add Default Admin if not exists
    c.execute("SELECT * FROM users WHERE username='admin'")
    if not c.fetchone():
        # Default password: 'admin' (sha256)
        # In production use bcrypt/argon2
        pw_hash = hashlib.sha256("admin".encode()).hexdigest()
        c.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)", 
                  ('admin', pw_hash, 'admin'))
    
    conn.commit()
    conn.close()

def verify_user(username, password):
    """Verify login credentials"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    pw_hash = hashlib.sha256(password.encode()).hexdigest()
    c.execute("SELECT role FROM users WHERE username=? AND password_hash=?", (username, pw_hash))
    user = c.fetchone()
    
    conn.close()
    return user[0] if user else None

def log_threat(threat_data):
    """Log a detected threat to DB"""
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        
        c.execute("INSERT INTO threats (timestamp, threat_type, source_ip, severity, action) VALUES (?, ?, ?, ?, ?)",
                  (threat_data['timestamp'], threat_data['threat'], threat_data['source_ip'], 
                   threat_data['severity'], threat_data['action']))
        
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"DB Error: {e}")

def get_recent_threats(limit=50):
    """Get recent threats for Admin Panel"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    
    c.execute("SELECT * FROM threats ORDER BY id DESC LIMIT ?", (limit,))
    rows = [dict(row) for row in c.fetchall()]
    
    conn.close()
    return rows
