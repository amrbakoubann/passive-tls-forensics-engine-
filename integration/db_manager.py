import sqlite3
import os

# ensuring the database is created in the project root
DB_PATH = os.path.join(os.path.dirname(__file__), '../forensics.db')

def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        # Table 1: dterministic Identity
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS fingerprints (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                source_ip TEXT,
                ja4_hash TEXT,
                sni TEXT
            )
        ''')
        # Table 2: AI Behavioral Logs
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS traffic_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                flow_id TEXT UNIQUE,
                packet_count INTEGER,
                byte_count INTEGER,
                ai_score REAL DEFAULT 0.0
            )
        ''')
        conn.commit()

def log_fingerprint(ip, ja4, sni):
    """The bridge function called by the sniffer"""
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO fingerprints (source_ip, ja4_hash, sni) VALUES (?, ?, ?)",
            (ip, ja4, sni)
        )
        conn.commit()

if __name__ == "__main__":
    init_db()
    print("[+] forensics.db initialized.")