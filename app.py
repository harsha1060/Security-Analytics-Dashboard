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
from datetime import datetime, timedelta
import geoip2.database
import geoip2.errors
from parse_logs import parse_and_store_logs # Import the robust parsing function

# --- CONFIGURATION ---
DB_FILE = 'log_data.db'
LOG_FILE = 'access.log' 
TARGET_URL = 'http://starfellharbor.mooo.com'
PARSING_INTERVAL_SECONDS = 10 # Update frequency

# --- Geolocation Library Setup ---
geo_reader = None
try:
    # Ensure this file is downloaded and placed in the project root
    geo_reader = geoip2.database.Reader('GeoLite2-City.mmdb') 
except ImportError:
    print("Warning: geoip2 library not found. Geographic data will not be available.")
except FileNotFoundError:
    # Removed the explicit FileNotFoundError check here as it's handled above,
    # but re-added the print statement for clarity in the setup phase.
    print("Warning: GeoLite2-City.mmdb database not found. Geographic data will not be available.")
except Exception as e:
    print(f"An error occurred during GeoIP setup: {e}")

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
        # This function intelligently only imports NEW lines
        parse_and_store_logs(LOG_FILE, DB_FILE)
        time.sleep(interval_seconds)

# --- Database Query Functions ---

def get_db_connection(db_path):
    """Helper to get a database connection."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row # Allows accessing columns by name
    return conn

def get_visitor_analytics(db_path):
    """Aggregates visitor data, including GeoIP lookup."""
    conn = get_db_connection(db_path)
    c = conn.cursor()
    
    # 1. Total hits
    c.execute("SELECT COUNT(id) AS total_hits FROM log_entries")
    total_hits = c.fetchone()['total_hits']

    # 2. Top paths
    c.execute("SELECT path, COUNT(id) AS hits FROM log_entries GROUP BY path ORDER BY hits DESC LIMIT 5")
    top_paths = [dict(row) for row in c.fetchall()]

    # 3. Top IP addresses
    c.execute("SELECT ip_address, COUNT(id) AS hits FROM log_entries GROUP BY ip_address ORDER BY hits DESC LIMIT 5")
    top_ips_raw = [dict(row) for row in c.fetchall()]

    # 4. GeoIP Lookup for IPs
    top_ips_geo = []
    for ip in top_ips_raw:
        ip_data = ip
        ip_data['country'] = 'Unknown'
        
        # ADDED ROBUSTNESS: Check if geo_reader is available
        if geo_reader:
            try:
                response = geo_reader.city(ip['ip_address'])
                ip_data['country'] = response.country.name
            except geoip2.errors.AddressNotFoundError:
                ip_data['country'] = 'Unknown IP'
            except ValueError:
                ip_data['country'] = 'Invalid IP'
            except Exception as e:
                # Catch any other GeoIP related error
                print(f"GeoIP Error for {ip['ip_address']}: {e}")
                
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

    # Get counts for all status codes
    c.execute("SELECT status_code, COUNT(id) AS count FROM log_entries GROUP BY status_code ORDER BY count DESC")
    status_codes_raw = [dict(row) for row in c.fetchall()]

    # Separate into categories
    summary = {
        'total': sum(item['count'] for item in status_codes_raw),
        'success_2xx': 0,
        'redirect_3xx': 0,
        'client_error_4xx': 0,
        'server_error_5xx': 0,
        'others': 0,
        'details': status_codes_raw
    }

    for item in status_codes_raw:
        code = item['status_code']
        count = item['count']
        
        if 200 <= code < 300:
            summary['success_2xx'] += count
        elif 300 <= code < 400:
            summary['redirect_3xx'] += count
        elif 400 <= code < 500:
            summary['client_error_4xx'] += count
        elif 500 <= code < 600:
            summary['server_error_5xx'] += count
        else:
            summary['others'] += count

    conn.close()
    return summary

def get_security_alerts(db_path):
    """
    Identifies potential security threats based on log data.
    E.g., high volume of 4xx errors from a single IP.
    """
    conn = get_db_connection(db_path)
    c = conn.cursor()
    
    # Thresholds for alerts
    ERROR_THRESHOLD = 10 
    
    # Find IPs with high number of client errors (4xx)
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
        alert['description'] = f"Potential scanning or probing activity. {alert['error_count']} client errors (4xx) out of {alert['total_count']} total requests."
        
        # GeoIP Lookup for the alert IP (if reader is available)
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


# --- External Analysis (Security Audit) ---

def analyze_external_security(url):
    """
    Performs a simple external audit of the target URL for common security issues.
    (This is simulated/mocked for the purpose of the dashboard)
    """
    # Renamed 'security_headers' to 'http_headers' to match the expected key in dashboard.html
    results = {'http_headers': [], 'port_scan': [], 'error': None} 
    
    try:
        # 1. Header Analysis
        response = requests.get(url, timeout=5)
        headers = response.headers
        
        missing_headers = []
        required_security_headers = [
            'Strict-Transport-Security',
            'X-Content-Type-Options',
            'X-Frame-Options',
            'Content-Security-Policy'
        ]
        
        for header in required_security_headers:
            if header not in headers:
                missing_headers.append({'header': header, 'status': 'MISSING', 'recommendation': f"Add the {header} header to prevent common attacks like clickjacking or XSS."})
            else:
                # Store data in the 'http_headers' list
                results['http_headers'].append({'header': header, 'status': 'PRESENT', 'value': headers[header]})
        
        # Extend the list with any missing headers
        results['http_headers'].extend(missing_headers)
        
        # 2. Mock Port Scan (for demonstration, actual scanning is complex and often blocked)
        # We will only check a few common ports
        hostname = url.replace('http://', '').replace('https://', '').split('/')[0]
        common_ports = [22, 80, 443]
        port_scan_results = []
        
        for port in common_ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result_code = sock.connect_ex((hostname, port))
            if result_code == 0:
                port_scan_results.append(f"Port {port} is OPEN")
            else:
                port_scan_results.append(f"Port {port} is CLOSED or filtered")
            sock.close()
        results['port_scan'] = port_scan_results
            
    except requests.exceptions.RequestException as e:
        results['error'] = f"Error accessing {url}: {e}"
    except socket.gaierror:
        results['error'] = "Error: Could not resolve hostname."
    except Exception as e:
        results['error'] = f"An unexpected error occurred during external analysis: {e}"
    
    return results

# --- Flask Application Routes ---
@app.route('/')
def dashboard():
    visitor_data = get_visitor_analytics(DB_FILE)
    security_alerts = get_security_alerts(DB_FILE)
    external_analysis = analyze_external_security(TARGET_URL)
    status_code_data = get_status_code_summary(DB_FILE) 
    
    return render_template('dashboard.html',
                           visitor_data=visitor_data,
                           security_alerts=security_alerts,
                           external_analysis=external_analysis,
                           status_code_data=status_code_data) 

if __name__ == '__main__':
    # 1. CRITICAL INITIALIZATION STEP: Load all existing log data once
    print("--- Running Initial Database Load ---")
    parse_and_store_logs(LOG_FILE, DB_FILE)
    print("--- Initial Load Complete. Starting Application ---\n")

    # 2. Start the continuous background update process (the internal parser)
    # This thread ensures that once the local access.log is updated (by automate_sync.py), 
    # the database is also updated without needing to restart app.py.
    parser_thread = threading.Thread(
        target=background_parser_task, 
        args=(PARSING_INTERVAL_SECONDS,), 
        daemon=True
    )
    parser_thread.start()
    
    # 3. Start the Flask server
    app.run(debug=True, use_reloader=False) # use_reloader=False prevents the background thread from being started twice