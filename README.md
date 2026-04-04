🛡️ Security Analytics Dashboard & Personal SIEM
================================================

**A lightweight, proactive security monitoring tool for real-time threat detection and active defense.**

This project is a Python-based **Personal SIEM** (Security Information and Event Management) tool. It transforms raw web server logs into an actionable security dashboard, allowing you to monitor traffic, detect probes, and **actively block malicious IPs** in real-time.

* * * * *

🚀 Key Features
---------------

-   **Real-Time Log Probing:** Automatically scans incoming logs for malicious patterns, including directory fuzzing and common exploit payloads.

-   **Active Defense (Live Blocking):** An integrated firewall interface that allows you to block/unblock malicious IP addresses directly from the dashboard.

-   **Dockerized Deployment:** Fully containerized using Docker and Docker Compose for "one-command" setup and environment isolation.

-   **Geographical Insights:** Integrated MaxMind GeoLite2 tracking to visualize the origin of attack vectors.

-   **Security Auditing:** Live network probing for missing HTTP security headers and open ports on the target infrastructure.

-   **Operational Intelligence:** Visualizes HTTP status codes (200, 403, 404, 500) to identify site health and bot scraping activity.

* * * * *

🛠️ Tech Stack
--------------

-   **Backend:** Python 3.x, Flask

-   **Database:** SQLite (for lightweight, portable log storage)

-   **DevOps:** Docker, Docker Compose

-   **Security:** Regex-based Log Analysis, Socket Programming (Port Scanning)

-   **Frontend:** HTML5, CSS3, Chart.js (for real-time analytics)

* * * * *

📦 Getting Started
------------------

### Prerequisites

-   & Docker Compose installed.

-   **MaxMind Database:** Download `GeoLite2-City.mmdb` from and place it in the root directory.

-   **Log File:** Ensure your web logs are in Combined Log Format and named `access_logs.tsv` (or update the config).

### Quick Start (Docker)

The fastest way to get the SIEM running:

The dashboard will be available at `http://localhost:5000`.

* * * * *

🔍 How It Works
---------------

### 1\. Log Ingestion & Parsing

The `parse_logs.py` engine utilizes regular expressions to deconstruct raw log strings into structured data (IP, Timestamp, Request Type, Status Code, etc.) and stores them in a local SQLite database for high-speed querying.

### 2\. Threat Detection Logic

The tool flags an IP as **"Suspicious"** if it meets specific criteria:

-   Exceeding a threshold of `403 Forbidden` or `404 Not Found` errors within a short window (Indicative of directory busting/fuzzing).

-   Presence of SQL injection strings (e.g., `UNION SELECT`, `' OR 1=1`) in request URIs.

### 3\. Active Mitigation

The **Live Blocking** module interfaces with the system's network layer (or simulated via the app interface) to drop packets from flagged IPs. You can manage the "Blacklist" directly through the **Security Management** tab in the UI.

* * * * *

📄 License
----------

Distributed under the MIT License. See `LICENSE` for more information.
