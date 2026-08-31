# Security Analytics Dashboard

A lightweight personal SIEM built to transform raw web server logs into an actionable security dashboard — with real-time threat detection, active IP blocking, and geographical attack visualization.

---

## Overview

Most homelab and self-hosted setups generate a steady stream of access logs that go unread. This project changes that: a Python/Flask application that ingests those logs, identifies malicious patterns, and gives you a live dashboard to monitor and respond to threats — including blocking offending IPs directly from the UI.

---

## Features

**Threat Detection**
- Regex-based log analysis flagging directory fuzzing, SQL injection attempts, and abnormal error-rate patterns
- Configurable thresholds for `403` and `404` error bursts (indicative of active enumeration)

**Active Defense**
- Block and unblock malicious IPs directly from the Security Management tab
- Interfaces with the system network layer to drop flagged traffic in real time

**Visibility**
- HTTP status code breakdown (`200`, `403`, `404`, `500`) for traffic health and bot detection
- MaxMind GeoLite2 integration for geographical origin tracking of attack vectors
- Live network probing for missing HTTP security headers and exposed ports on your infrastructure

**Deployment**
- Fully Dockerized — single command to bring the entire stack up
- SQLite backend for portable, dependency-free log storage

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.x, Flask |
| Database | SQLite |
| Frontend | HTML5, CSS3, Chart.js |
| DevOps | Docker, Docker Compose |
| Security | Regex log analysis, Socket programming |

---

## Getting Started

### Prerequisites

- Docker and Docker Compose installed
- MaxMind GeoLite2 database — download `GeoLite2-City.mmdb` from [maxmind.com](https://www.maxmind.com) and place it in the project root
- Web server logs in Combined Log Format, named `access_logs.tsv` (or update the path in config)

### Quick Start

```bash
docker compose up --build
```

Dashboard available at `http://localhost:5000`.

---

## How It Works

### Log Ingestion
`parse_logs.py` uses regular expressions to break raw log strings into structured records — IP, timestamp, request type, status code, URI — and stores them in SQLite for fast querying.

### Threat Detection
An IP is flagged as suspicious when it:
- Exceeds the configured threshold of `403` or `404` responses within a short time window (directory busting indicator)
- Contains known injection strings in the request URI (`UNION SELECT`, `' OR 1=1`, etc.)

### Active Mitigation
Flagged IPs appear in the Security Management tab. Blocking an IP interfaces with the system's network layer to drop its packets. The blocklist is fully manageable from the dashboard without touching the command line.

---

## License

Distributed under the MIT License. See `LICENSE` for details.
