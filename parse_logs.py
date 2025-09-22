import re
import sqlite3
import os

def parse_and_store_logs(log_file_path, db_file_path):
    """Parses log file entries and stores them in a SQLite database."""
    # This regex is specifically for the standard Combined Log Format
    log_pattern = re.compile(r'(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) (\S+)" (\d+) (\d+) "([^"]*)" "([^"]*)"')
    
    conn = sqlite3.connect(db_file_path)
    c = conn.cursor()

    print("Starting to parse and store log data...")
    parsed_count = 0

    try:
        with open(log_file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for i, line in enumerate(f):
                line = line.strip()
                if not line:
                    continue

                match = log_pattern.match(line)
                if match:
                    parsed_count += 1
                    
                    # Unpack the matched groups
                    ip_address, timestamp, method, path, protocol, status_code, bytes_sent, referer, user_agent = match.groups()
                    
                    parsed_data = (
                        ip_address,
                        timestamp,
                        method,
                        path,
                        int(status_code),
                        int(bytes_sent),
                        referer,
                        user_agent
                    )
                    
                    c.execute('''
                        INSERT INTO log_entries (ip_address, timestamp, method, path, status_code, bytes_sent, referer, user_agent)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ''', parsed_data)

                if (i + 1) % 10000 == 0:
                    conn.commit()
                    print(f"Committed {i+1} lines...")

        conn.commit()
        print(f"Successfully parsed and stored {parsed_count} rows.")
        if parsed_count == 0:
            print("No log lines were parsed. The regex pattern might be incorrect for your file's format.")
            
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        conn.close()

if __name__ == '__main__':
    LOG_FILE_NAME = 'nasa_access.tsv' 
    DB_FILE_NAME = 'log_data.db'
    
    if not os.path.exists(LOG_FILE_NAME):
        print(f"Error: The file '{LOG_FILE_NAME}' was not found.")
    else:
        parse_and_store_logs(LOG_FILE_NAME, DB_FILE_NAME)