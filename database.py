import sqlite3

def setup_database():
    conn = sqlite3.connect('log_data.db')
    c = conn.cursor()

    # Existing table
    c.execute('''
        CREATE TABLE IF NOT EXISTS log_entries (
            id INTEGER PRIMARY KEY,
            ip_address TEXT,
            timestamp TEXT,
            method TEXT,
            path TEXT,
            status_code INTEGER,
            bytes_sent INTEGER,
            referer TEXT,
            user_agent TEXT
        )
    ''')

    # NEW TABLE: To track blocked IPs
    c.execute('''
        CREATE TABLE IF NOT EXISTS blocked_ips (
            id INTEGER PRIMARY KEY,
            ip_address TEXT UNIQUE,
            blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    conn.commit()
    conn.close()

if __name__ == '__main__':
    setup_database()
    print("Database updated with 'blocked_ips' table.")