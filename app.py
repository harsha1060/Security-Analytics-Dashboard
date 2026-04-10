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
import geoip2.database
import geoip2.errors
from parse_logs import parse_and_store_logs 

# --- CONFIGURATION ---
DB_FILE = 'log_data.db'
LOG_FILE = 'access.log' 
TARGET_URL = 'http://starfellharbor.mooo.com'
PARSING_INTERVAL_SECONDS = 10 

# --- SSH CONFIGURATION FOR ACTIVE BLOCKING ---
# IMPORTANT: Use the path INSIDE the Docker container
SSH_KEY_PATH = '/root/login.pem'
REMOTE_USER = 'ubuntu'
REMOTE_HOST = 'ec2-3-80-121-33.compute-1.amazonaws.com'

# --- Geolocation Library Setup ---
geo_reader = None
try:
    geo_reader = geoip2.database.Reader('GeoLite2-City.mmdb') 
except Exception as e:
    print(f"Warning: GeoIP geographic data will not be available: {e}")

app = Flask(__name__)

# --- Background Parsing Thread Functions ---
def background_parser_task(interval_seconds):
    print(f"Starting continuous log parser. Interval: {interval_seconds}s...")
    if not os.path.exists(DB_FILE):
        return
    while True:
        parse_and_store_logs(LOG_FILE, DB_FILE)
        time.sleep(interval_seconds)

def get_db_connection(db_path):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn

def get_currently_blocked_ips(db_path):
    conn = get_db_connection(db_path)
    c = conn.cursor()
    c.execute("SELECT ip_address, blocked_at FROM blocked_ips ORDER BY blocked_at DESC")
    blocks = [dict(row) for row in c.fetchall()]
    conn.close()
    return blocks

def get_visitor_analytics(db_path):
    conn = get_db_connection(db_path)
    c = conn.cursor()
    total_hits = c.execute("SELECT COUNT(id) FROM log_entries").fetchone()[0]
    top_paths = [dict(row) for row in c.execute("SELECT path, COUNT(id) AS hits FROM log_entries GROUP BY path ORDER BY hits DESC LIMIT 5").fetchall()]
    top_ips_raw = [dict(row) for row in c.execute("SELECT ip_address, COUNT(id) AS hits FROM log_entries GROUP BY ip_address ORDER BY hits DESC LIMIT 5").fetchall()]
    top_ips_geo = []
    for ip in top_ips_raw:
        ip_data = dict(ip)
        ip_data['country'] = 'Unknown'
        if geo_reader:
            try:
                response = geo_reader.city(ip['ip_address'])
                ip_data['country'] = response.country.name
            except: pass
        top_ips_geo.append(ip_data)
    conn.close()
    return {'total_hits': total_hits, 'top_paths': top_paths, 'top_ips': top_ips_geo}

def get_status_code_summary(db_path):
    conn = get_db_connection(db_path)
    c = conn.cursor()
    status_codes_raw = [dict(row) for row in c.execute("SELECT status_code, COUNT(id) AS count FROM log_entries GROUP BY status_code ORDER BY count DESC").fetchall()]
    summary = {'total': sum(item['count'] for item in status_codes_raw), 'success_2xx': 0, 'redirect_3xx': 0, 'client_error_4xx': 0, 'server_error_5xx': 0, 'others': 0, 'details': status_codes_raw}
    for item in status_codes_raw:
        code = item['status_code']
        count = item['count']
        if 200 <= code < 300: summary['success_2xx'] += count
        elif 400 <= code < 500: summary['client_error_4xx'] += count
    conn.close()
    return summary

def get_security_alerts(db_path):
    conn = get_db_connection(db_path)
    c = conn.cursor()
    alerts = []
    for row in c.execute("SELECT ip_address, COUNT(id) AS errs FROM log_entries WHERE status_code >= 400 GROUP BY ip_address HAVING errs >= 10").fetchall():
        alert = dict(row)
        alert['description'] = f"Potential scanning. {alert['errs']} errors."
        alert['location'] = 'Unknown'
        alerts.append(alert)
    conn.close()
    return alerts

def analyze_external_security(url):
    results = {'http_headers': [], 'port_scan': []}
    try:
        response = requests.get(url, timeout=5)
        for h in ['Strict-Transport-Security', 'X-Frame-Options']:
            results['http_headers'].append({'header': h, 'status': 'PRESENT' if h in response.headers else 'MISSING'})
    except: pass
    return results

# --- Flask Application Routes ---
@app.route('/')
def dashboard():
    visitor_data = get_visitor_analytics(DB_FILE)
    security_alerts = get_security_alerts(DB_FILE)
    external_analysis = analyze_external_security(TARGET_URL)
    status_code_data = get_status_code_summary(DB_FILE) 
    blocked_ips = get_currently_blocked_ips(DB_FILE)
    return render_template('dashboard.html', visitor_data=visitor_data, security_alerts=security_alerts, external_analysis=external_analysis, status_code_data=status_code_data, blocked_ips=blocked_ips, TARGET_URL=TARGET_URL) 

@app.route('/block/<ip_address>', methods=['POST'])
def block_ip(ip_address):
    if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip_address):
        return json.dumps({"status": "error", "message": "Invalid IP format"}), 400

    remote_command = f"sudo iptables -A INPUT -s {ip_address} -j DROP"
    
    # ADDED SSH OPTIONS: 
    # -o StrictHostKeyChecking=no bypasses the "Trust this host?" fingerprint prompt
    ssh_cmd = [
        'ssh', '-i', SSH_KEY_PATH, 
        '-o', 'StrictHostKeyChecking=no',
        f"{REMOTE_USER}@{REMOTE_HOST}", 
        remote_command
    ]

    try:
        subprocess.run(ssh_cmd, capture_output=True, text=True, check=True)
        conn = get_db_connection(DB_FILE)
        conn.execute("INSERT OR IGNORE INTO blocked_ips (ip_address) VALUES (?)", (ip_address,))
        conn.commit()
        conn.close()
        return json.dumps({"status": "success", "message": f"IP {ip_address} blocked successfully."})
    except subprocess.CalledProcessError as e:
        return json.dumps({"status": "error", "message": f"SSH Error: {e.stderr}"}), 500
    except Exception as e:
        return json.dumps({"status": "error", "message": str(e)}), 500

@app.route('/unblock/<ip_address>', methods=['POST'])
def unblock_ip(ip_address):
    remote_command = f"sudo iptables -D INPUT -s {ip_address} -j DROP"
    ssh_cmd = [
        'ssh', '-i', SSH_KEY_PATH, 
        '-o', 'StrictHostKeyChecking=no',
        f"{REMOTE_USER}@{REMOTE_HOST}", 
        remote_command
    ]
    try:
        subprocess.run(ssh_cmd, capture_output=True, text=True, check=True)
        conn = get_db_connection(DB_FILE)
        conn.execute("DELETE FROM blocked_ips WHERE ip_address = ?", (ip_address,))
        conn.commit()
        conn.close()
        return json.dumps({"status": "success", "message": f"IP {ip_address} unblocked successfully."})
    except Exception as e:
        return json.dumps({"status": "error", "message": str(e)}), 500

if __name__ == '__main__':
    parse_and_store_logs(LOG_FILE, DB_FILE)
    threading.Thread(target=background_parser_task, args=(PARSING_INTERVAL_SECONDS,), daemon=True).start()
    app.run(host='0.0.0.0', port=5000, debug=True, use_reloader=False)