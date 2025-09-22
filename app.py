from flask import Flask, render_template
import sqlite3
import os
import requests
import socket
import geoip2.database
import geoip2.errors

# --- Configuration ---
GEO_DB_PATH = 'GeoLite2-City.mmdb'
DB_FILE = 'log_data.db'
TARGET_URL = 'http://testphp.vulnweb.com'

# --- App Initialization ---
app = Flask(__name__)

# --- Geolocation Library Setup ---
try:
    geo_reader = geoip2.database.Reader(GEO_DB_PATH)
except (IOError, FileNotFoundError) as e:
    print(f"Failed to load GeoLite2 database: {e}. Geolocation features will be disabled.")
    geo_reader = None

# --- Helper Functions for Data Retrieval ---
def get_db_connection():
    """Establishes a connection to the SQLite database."""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row  # This allows accessing columns by name
    return conn

def get_visitor_analytics():
    """Fetches key visitor statistics from the database."""
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            
            total_visits = c.execute("SELECT COUNT(*) FROM log_entries").fetchone()[0]
            unique_visitors = c.execute("SELECT COUNT(DISTINCT ip_address) FROM log_entries").fetchone()[0]
            top_pages = c.execute("SELECT path, COUNT(*) AS count FROM log_entries GROUP BY path ORDER BY count DESC LIMIT 5").fetchall()
            
            # Geolocation analysis for top countries
            country_counts = {}
            if geo_reader:
                ip_counts = c.execute("SELECT ip_address, COUNT(*) FROM log_entries GROUP BY ip_address").fetchall()
                for ip, count in ip_counts:
                    try:
                        response = geo_reader.city(ip)
                        country = response.country.name
                        if country:
                            country_counts[country] = country_counts.get(country, 0) + count
                    except geoip2.errors.AddressNotFoundError:
                        continue
            
            sorted_countries = sorted(country_counts.items(), key=lambda item: item[1], reverse=True)[:5]
            
            return {
                'total_visits': total_visits,
                'unique_visitors': unique_visitors,
                'top_pages': [{'page': row['path'], 'count': row['count']} for row in top_pages],
                'top_countries': [{'country': item[0], 'count': item[1]} for item in sorted_countries]
            }
    except Exception as e:
        print(f"Error in visitor analytics: {e}")
        return {'total_visits': 0, 'unique_visitors': 0, 'top_pages': [], 'top_countries': []}

def get_security_alerts():
    """Fetches potential security alerts from the database."""
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            
            brute_force_attempts = c.execute("SELECT ip_address, COUNT(*) AS count FROM log_entries WHERE status_code = 401 GROUP BY ip_address HAVING count > 5 ORDER BY count DESC").fetchall()
            scanning_attempts = c.execute("SELECT ip_address, COUNT(*) AS count FROM log_entries WHERE status_code = 404 GROUP BY ip_address HAVING count > 10 ORDER BY count DESC").fetchall()

            return {
                'brute_force_attempts': [{'ip': row['ip_address'], 'errors': row['count']} for row in brute_force_attempts],
                'scanning_attempts': [{'ip': row['ip_address'], 'errors': row['count']} for row in scanning_attempts]
            }
    except Exception as e:
        print(f"Error in security checks: {e}")
        return {'brute_force_attempts': [], 'scanning_attempts': []}

def get_status_code_analytics():
    """Fetches counts of common HTTP status codes."""
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            status_counts = {}
            status_codes = [200, 301, 302, 304, 400, 401, 403, 404, 500]
            for code in status_codes:
                count = c.execute("SELECT COUNT(*) FROM log_entries WHERE status_code = ?", (code,)).fetchone()[0]
                status_counts[code] = count
            
            # Count the total number of 2xx, 3xx, 4xx, and 5xx responses
            ok_count = c.execute("SELECT COUNT(*) FROM log_entries WHERE status_code LIKE '2%'").fetchone()[0]
            redirect_count = c.execute("SELECT COUNT(*) FROM log_entries WHERE status_code LIKE '3%'").fetchone()[0]
            client_error_count = c.execute("SELECT COUNT(*) FROM log_entries WHERE status_code LIKE '4%'").fetchone()[0]
            server_error_count = c.execute("SELECT COUNT(*) FROM log_entries WHERE status_code LIKE '5%'").fetchone()[0]

            return {
                'individual_codes': status_counts,
                'summary': {
                    'ok': ok_count,
                    'redirect': redirect_count,
                    'client_error': client_error_count,
                    'server_error': server_error_count
                }
            }
    except Exception as e:
        print(f"Error in status code analytics: {e}")
        return {'individual_codes': {}, 'summary': {}}

# --- External Security Analysis Functions ---
def check_security_headers(headers):
    """Checks for the presence of key security headers."""
    security_headers = {
        'Strict-Transport-Security': 'HSTS is not set',
        'Content-Security-Policy': 'CSP is not set',
        'X-Frame-Options': 'XFO is not set',
        'X-Content-Type-Options': 'XCTO is not set'
    }
    return {header: headers.get(header, default) for header, default in security_headers.items()}

def check_tech_stack(headers):
    """Identifies the server and powered-by headers."""
    tech_stack = {}
    if 'Server' in headers:
        tech_stack['Server'] = headers['Server']
    if 'X-Powered-By' in headers:
        tech_stack['Powered By'] = headers['X-Powered-By']
    return tech_stack

def perform_port_scan(hostname):
    """Performs a basic port scan on common ports."""
    ports_to_check = [80, 443, 22, 21]
    open_ports = []
    for port in ports_to_check:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)
                result = sock.connect_ex((hostname, port))
                if result == 0:
                    open_ports.append(f"Port {port} is OPEN")
        except socket.gaierror:
            return [f"Error: Could not resolve hostname for {hostname}"]
        except Exception as e:
            return [f"An unexpected error occurred during port scan: {e}"]
    return open_ports

def analyze_external_security(url):
    """Orchestrates external security checks."""
    results = {}
    try:
        response = requests.get(url, timeout=10)
        results['security_headers'] = check_security_headers(response.headers)
        results['tech_stack'] = check_tech_stack(response.headers)
        
        hostname = url.replace('https://', '').replace('http://', '').split('/')[0]
        results['port_scan'] = perform_port_scan(hostname)

    except requests.exceptions.RequestException as e:
        results['error'] = f"Error accessing {url}: {e}"
        results['security_headers'] = {}
        results['tech_stack'] = {}
        results['port_scan'] = []
    
    return results

# --- Flask Application Routes ---
@app.route('/')
def dashboard():
    visitor_data = get_visitor_analytics()
    security_alerts = get_security_alerts()
    status_code_data = get_status_code_analytics()
    external_analysis = analyze_external_security(TARGET_URL)

    return render_template('dashboard.html',
                           visitor_data=visitor_data,
                           security_alerts=security_alerts,
                           status_code_data=status_code_data,
                           external_analysis=external_analysis)

if __name__ == '__main__':
    app.run(debug=True, port=5000)