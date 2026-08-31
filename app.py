from flask import Flask, render_template
import sqlite3
import re
import time
import os
import threading
import json
import requests
from bs4 import BeautifulSoup
import socket
import subprocess
from datetime import datetime, timedelta
import geoip2.database  # --> Make sure to install the geoip2 library via pip
import geoip2.errors    # --> For handling exceptions when IPs are not found in the GeoIP database
from parse_logs import parse_and_store_logs 

# --- CONFIGURATION ---
DB_FILE = 'log_data.db'
LOG_FILE = 'access.log' 
TARGET_URL = 'http://starfellharbor.mooo.com'
PARSING_INTERVAL_SECONDS = 10 # Update frequency

# --- SSH CONFIGURATION FOR ACTIVE BLOCKING ---
# Ensure the path to your .pem key is correct and accessible by this script
SSH_KEY_PATH = '/app/login.pem'
REMOTE_USER = 'ubuntu'
REMOTE_HOST = 'ec2-3-80-121-33.compute-1.amazonaws.com'

# --- Geolocation Library Setup ---
geo_reader = None
try:
    # Ensure this file is downloaded and placed in the project root
    geo_reader = geoip2.database.Reader('GeoLite2-City.mmdb') 
except Exception as e:
    print(f"Warning: GeoIP geographic data will not be available: {e}")

app = Flask(__name__)

# --- Background Parsing Thread Functions ---

def background_parser_task(interval_seconds):
    """
    Runs the log parsing script repeatedly in a separate, daemonized thread.
    This thread monitors the LOCAL access.log for changes.
    """
    print(f"Starting continuous log parser. Interval: {interval_seconds}s...")
    
    if not os.path.exists(DB_FILE):
        print(f"Database file {DB_FILE} not found. Ensure you run 'python database.py' first.")
        return

    while True:
        # imports NEW lines
        parse_and_store_logs(LOG_FILE, DB_FILE)
        time.sleep(interval_seconds)

# --- Database Query Helpers ---

def get_db_connection(db_path):
    """Helper to get a database connection."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row # Allows accessing columns by name
    return conn

def get_currently_blocked_ips(db_path):
    """Fetches the list of blocked IPs from the local database."""
    conn = get_db_connection(db_path)
    c = conn.cursor()
    c.execute("SELECT ip_address, blocked_at FROM blocked_ips ORDER BY blocked_at DESC")
    blocks = [dict(row) for row in c.fetchall()]
    conn.close()
    return blocks

# --- Analytics Functions ---

def get_visitor_analytics(db_path):
    """Aggregates visitor data, including GeoIP lookup."""
    conn = get_db_connection(db_path)
    c = conn.cursor()
    
    c.execute("SELECT COUNT(id) FROM log_entries")
    total_hits = c.fetchone()[0]

    c.execute("SELECT path, COUNT(id) AS hits FROM log_entries GROUP BY path ORDER BY hits DESC LIMIT 5")
    top_paths = [dict(row) for row in c.fetchall()]

    c.execute("SELECT ip_address, COUNT(id) AS hits FROM log_entries GROUP BY ip_address ORDER BY hits DESC LIMIT 5")
    top_ips_raw = [dict(row) for row in c.fetchall()]

    top_ips_geo = []
    for ip in top_ips_raw:
        ip_data = dict(ip)
        ip_data['country'] = 'Unknown'
        if geo_reader:
            try:
                response = geo_reader.city(ip['ip_address'])
                ip_data['country'] = response.country.name
            except (geoip2.errors.AddressNotFoundError, ValueError):
                pass
        top_ips_geo.append(ip_data)

    conn.close()
    return {
        'total_hits': total_hits,
        'top_paths': top_paths,
        'top_ips': top_ips_geo
    }

def get_status_code_summary(db_path):
    """Aggregates status code data."""
    conn = get_db_connection(db_path)
    c = conn.cursor()

    c.execute("SELECT status_code, COUNT(id) AS count FROM log_entries GROUP BY status_code ORDER BY count DESC")
    status_codes_raw = [dict(row) for row in c.fetchall()]

    summary = {
        'total': sum(item['count'] for item in status_codes_raw),
        'success_2xx': 0, 'redirect_3xx': 0, 'client_error_4xx': 0, 'server_error_5xx': 0, 'others': 0,
        'details': status_codes_raw
    }

    for item in status_codes_raw:
        code = item['status_code']
        count = item['count']
        if 200 <= code < 300: summary['success_2xx'] += count
        elif 300 <= code < 400: summary['redirect_3xx'] += count
        elif 400 <= code < 500: summary['client_error_4xx'] += count
        elif 500 <= code < 600: summary['server_error_5xx'] += count
        else: summary['others'] += count

    conn.close()
    return summary

def get_security_alerts(db_path):
    """Identifies potential security threats based on 4xx error bursts."""
    conn = get_db_connection(db_path)
    c = conn.cursor()
    ERROR_THRESHOLD = 10 
    
    c.execute("""
        SELECT ip_address, COUNT(id) AS error_count, 
               (SELECT COUNT(id) FROM log_entries WHERE ip_address = t1.ip_address) AS total_count
        FROM log_entries t1
        WHERE status_code >= 400 AND status_code < 500
        GROUP BY ip_address
        HAVING error_count >= ?
        ORDER BY error_count DESC
        LIMIT 10
    """, (ERROR_THRESHOLD,))
    
    alerts = []
    for row in c.fetchall():
        alert = dict(row)
        alert['description'] = f"Potential scanning/probing. {alert['error_count']} client errors (4xx) out of {alert['total_count']} total requests."
        alert['location'] = 'Unknown'
        if geo_reader:
            try:
                response = geo_reader.city(alert['ip_address'])
                alert['location'] = f"{response.country.name} ({response.city.name if response.city.name else 'City Unknown'})"
            except (geoip2.errors.AddressNotFoundError, ValueError):
                pass
        alerts.append(alert)
        
    conn.close()
    return alerts

def analyze_external_security(url):
    """Performs an external audit of headers and ports."""
    results = {'http_headers': [], 'port_scan': [], 'error': None} 
    try:
        response = requests.get(url, timeout=5)
        headers = response.headers
        required_security_headers = [
            'Strict-Transport-Security', 'X-Content-Type-Options',
            'X-Frame-Options', 'Content-Security-Policy'
        ]
        for header in required_security_headers:
            if header not in headers:
                results['http_headers'].append({'header': header, 'status': 'MISSING', 'recommendation': f"Add {header} header."})
            else:
                results['http_headers'].append({'header': header, 'status': 'PRESENT', 'value': headers[header]})
        
        hostname = url.replace('http://', '').replace('https://', '').split('/')[0]
        for port in [22, 80, 443]:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result_code = sock.connect_ex((hostname, port))
            results['port_scan'].append(f"Port {port} is {'OPEN' if result_code == 0 else 'CLOSED'}")
            sock.close()
    except Exception as e:
        results['error'] = str(e)
    return results

# --- Flask Application Routes ---

@app.route('/')
def dashboard():
    visitor_data = get_visitor_analytics(DB_FILE)
    security_alerts = get_security_alerts(DB_FILE)
    external_analysis = analyze_external_security(TARGET_URL)
    status_code_data = get_status_code_summary(DB_FILE) 
    blocked_ips = get_currently_blocked_ips(DB_FILE)
    
    return render_template('dashboard.html',
                           visitor_data=visitor_data,
                           security_alerts=security_alerts,
                           external_analysis=external_analysis,
                           status_code_data=status_code_data,
                           blocked_ips=blocked_ips,
                           TARGET_URL=TARGET_URL) 

@app.route('/block/<ip_address>', methods=['POST'])
def block_ip(ip_address):
    """Executes remote SSH command to block the IP and logs it in the DB."""
    if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip_address):
        return json.dumps({"status": "error", "message": "Invalid IP format"}), 400

    # Command to add rule
    remote_command = f"sudo iptables -A INPUT -s {ip_address} -j DROP"
    ssh_cmd = ['ssh', '-i', SSH_KEY_PATH, f"{REMOTE_USER}@{REMOTE_HOST}", remote_command]

    try:
        subprocess.run(ssh_cmd, capture_output=True, text=True, check=True)
        
        # Log block in database
        conn = get_db_connection(DB_FILE)
        c = conn.cursor()
        c.execute("INSERT OR IGNORE INTO blocked_ips (ip_address) VALUES (?)", (ip_address,))
        conn.commit()
        conn.close()
        
        return json.dumps({"status": "success", "message": f"IP {ip_address} blocked successfully."})
    except subprocess.CalledProcessError as e:
        return json.dumps({"status": "error", "message": f"SSH Error: {e.stderr}"}), 500
    except Exception as e:
        return json.dumps({"status": "error", "message": str(e)}), 500

@app.route('/unblock/<ip_address>', methods=['POST'])
def unblock_ip(ip_address):
    """Removes IP from remote iptables and deletes the log from the DB."""
    # Command to DELETE the specific rule for this IP
    remote_command = f"sudo iptables -D INPUT -s {ip_address} -j DROP"
    ssh_cmd = ['ssh', '-i', SSH_KEY_PATH, f"{REMOTE_USER}@{REMOTE_HOST}", remote_command]

    try:
        subprocess.run(ssh_cmd, capture_output=True, text=True, check=True)
        
        # Remove from local database
        conn = get_db_connection(DB_FILE)
        c = conn.cursor()
        c.execute("DELETE FROM blocked_ips WHERE ip_address = ?", (ip_address,))
        conn.commit()
        conn.close()
        
        return json.dumps({"status": "success", "message": f"IP {ip_address} unblocked successfully."})
    except subprocess.CalledProcessError as e:
        # If the rule doesn't exist anymore on the server, we should still clean up our DB
        if "Bad rule" in e.stderr:
            conn = get_db_connection(DB_FILE)
            conn.execute("DELETE FROM blocked_ips WHERE ip_address = ?", (ip_address,))
            conn.commit()
            conn.close()
            return json.dumps({"status": "success", "message": "Rule already removed from server. Dashboard updated."})
        return json.dumps({"status": "error", "message": e.stderr}), 500
    except Exception as e:
        return json.dumps({"status": "error", "message": str(e)}), 500

if __name__ == '__main__':
    # 1. Run initial parsing
    print("--- Running Initial Database Load ---")
    parse_and_store_logs(LOG_FILE, DB_FILE)
    print("--- Initial Load Complete ---\n")

    # 2. Start background update thread
    parser_thread = threading.Thread(
        target=background_parser_task, 
        args=(PARSING_INTERVAL_SECONDS,), 
        daemon=True
    )
    parser_thread.start()
    
    # 3. Start Flask
    app.run(host='0.0.0.0', port=5000, debug=True, use_reloader=False)