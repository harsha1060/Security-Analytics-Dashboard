import sqlite3

def setup_database():
    conn = sqlite3.connect('log_data.db')
    c = conn.cursor()

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
    conn.commit()
    conn.close()

if __name__ == '__main__':
    setup_database()
    print("Database 'log_data.db' and table 'log_entries' created successfully.")