import re
import sqlite3
import os
import time

LOG_PATTERN = re.compile(r'(\S+) \S+ \S+ \[([^\]]+)\] \"(\S+) (\S+) (.*?)\" (\d+) (\S+) \"([^\"]*)\" \"([^\"]*)\"')

def parse_and_store_logs(log_file_path, db_file_path):
    """
    Parses log file entries, ensuring synchronization with the database based on existing row count.
    This is the function called continuously by the app.py background thread.
    """
    conn = sqlite3.connect(db_file_path)
    c = conn.cursor()

    try:
        # 1. Get current row count from the database
        c.execute("SELECT COUNT(id) FROM log_entries")
        db_row_count = c.fetchone()[0]
        
        # 2. Read all lines from the log file (Force fresh read from disk)
        try:
            with open(log_file_path, 'r', encoding='utf-8', errors='ignore') as f:
                all_lines = f.readlines()
        except FileNotFoundError:
            return

        log_file_total_lines = len(all_lines)
        
        # 3. CRITICAL CHECK: If log file hasn't grown beyond the committed count, do nothing.
        if log_file_total_lines <= db_row_count:
            return 

        # 4. Process only the NEW lines: This prevents the duplication.
        new_lines = all_lines[db_row_count:]
        new_entries = []

        for line in new_lines:
            line = line.strip()
            if not line:
                continue

            match = LOG_PATTERN.match(line)
            if match:
                # Unpack the matched groups
                (ip_address, timestamp, method, path, protocol, status_code_raw, 
                 bytes_sent_raw, referer, user_agent) = match.groups()
                
                # Robust Data Type Conversion
                try:
                    status_code = int(status_code_raw)
                except ValueError:
                    status_code = 0 
                
                try:
                    bytes_sent = int(bytes_sent_raw) if bytes_sent_raw.isdigit() else 0
                except ValueError:
                    bytes_sent = 0

                parsed_data = (
                    ip_address, timestamp, method, path, status_code, 
                    bytes_sent, referer, user_agent
                )
                
                new_entries.append(parsed_data)
            # ELSE: Skipped log lines will not cause duplication.

        # 5. Insert all new entries in a single batch
        if new_entries:
            c.executemany('''
                INSERT INTO log_entries (ip_address, timestamp, method, path, status_code, bytes_sent, referer, user_agent)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', new_entries)
            
            conn.commit()
            print(f"[{time.strftime('%H:%M:%S')}] Committed {len(new_entries)} NEW log lines to DB. New total DB rows: {db_row_count + len(new_entries)}")
            
    except Exception as e:
        print(f"[{time.strftime('%H:%M:%S')}] CRITICAL PARSING ERROR: {e}")
    finally:
        conn.close()

if __name__ == '__main__':
    # This block is for manual testing only.
    LOG_FILE_NAME = 'access.log' 
    DB_FILE_NAME = 'log_data.db'
    
    # NOTE: The manual run logic here needs to be simple for diagnostics.
    print("Manual run is disabled. Please use 'python app.py' to run the dashboard.")