import sqlite3

def init_db():
    conn = sqlite3.connect('forensics.db')
    cursor = conn.cursor()
    
    # TABLE 1: Identified JA4 Fingerprints
    # Stores the unique hardware/software signature of the client
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS fingerprints (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            source_ip TEXT,
            ja4_hash TEXT,
            is_malicious BOOLEAN DEFAULT 0,
            user_agent_label TEXT
        )
    ''')
    
    # TABLE 2: AI Traffic Logs
    # Stores the numerical features Member B will use for training/inference
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS traffic_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            flow_id TEXT UNIQUE,
            packet_count INTEGER,
            byte_count INTEGER,
            avg_packet_size REAL,
            ai_score REAL DEFAULT 0.0
        )
    ''')
    
    conn.commit()
    conn.close()
    print("[+] forensics.db initialized successfully.")

if __name__ == "__main__":
    init_db()