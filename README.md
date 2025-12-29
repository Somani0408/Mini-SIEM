
# Mini SIEM + SOC Dashboard

A comprehensive Security Information and Event Management (SIEM) system with Security Operations Center (SOC) dashboard capabilities for collecting, analyzing, and visualizing security events from Linux systems.

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
- [Detection Rules](#detection-rules)
- [MITRE ATT&CK Mapping](#mitre-attck-mapping)
- [SOC Workflow](#soc-workflow)
- [Screenshots](#screenshots)

## 🎯 Overview

This Mini SIEM system provides:

- **Log Collection**: Automated collection of authentication, SSH, and system logs from Linux systems
- **Log Parsing & Normalization**: Python-based parsers for multiple log formats
- **Security Event Detection**: Automated detection of brute force attacks, abnormal login patterns, and suspicious IP behavior
- **Alert Classification**: SOC-style alert classification (Low/Medium/High severity)
- **Visualization**: Kibana dashboards for real-time security monitoring
- **MITRE ATT&CK Mapping**: Each alert mapped to MITRE ATT&CK techniques

## ✨ Features

### Log Collection
- Authentication logs (`/var/log/auth.log`)
- SSH connection logs
- System logs (`/var/log/syslog`)
- Custom log normalization for Elasticsearch

### Security Event Detection
- **Brute Force Attacks**: Detects repeated failed login attempts from same IP
- **Abnormal Login Patterns**: Identifies unusual login times and locations
- **Suspicious IP Behavior**: Flags IPs with multiple failed attempts and port scanning

### Dashboard Visualizations
- Failed vs Successful Login Metrics
- Top Attacking IPs
- Alert Severity Distribution
- Timeline of Security Events
- Geographic IP Mapping (if GeoIP enabled)

### SOC Features
- MITRE ATT&CK technique mapping for each alert
- Alert classification (Low/Medium/High)
- Detailed alert descriptions with context
- Flask-based alert summary dashboard

## 🏗️ Architecture

```
┌─────────────┐
│ Linux System│
│  Log Files  │
└──────┬──────┘
       │
       ▼
┌─────────────┐
│ Log Parser  │ ◄─── Sample Logs
│   (Python)  │
└──────┬──────┘
       │ Normalized Data
       ▼
┌─────────────┐
│ Elasticsearch│
│   (Storage) │
└──────┬──────┘
       │
       ├──────────────┐
       ▼              ▼
┌─────────────┐  ┌─────────────┐
│   Kibana    │  │   Flask     │
│  Dashboard  │  │   Frontend  │
└─────────────┘  └─────────────┘
       │              │
       └──────┬───────┘
              ▼
       ┌─────────────┐
       │   SOC Team  │
       │  Dashboard  │
       └─────────────┘
```

## 📁 Project Structure

```
Mini SIEM/
│
├── logs/                      # Sample log files
│   ├── auth.log              # Authentication logs
│   ├── ssh.log               # SSH connection logs
│   └── syslog.log            # System logs
│
├── scripts/                   # Python scripts
│   ├── log_parser.py         # Main log parser
│   ├── log_collector.py      # Log collection script
│   ├── event_detector.py     # Security event detection
│   └── es_indexer.py         # Elasticsearch indexer
│
├── simulators/                # Security event simulators
│   ├── brute_force_sim.py    # Brute force attack simulator
│   ├── port_scan_sim.py      # Port scanning simulator
│   └── failed_login_sim.py   # Failed login simulator
│
├── detection/                 # Detection rules
│   ├── rules.py              # Detection rule definitions
│   └── mitre_mapping.json    # MITRE ATT&CK mappings
│
├── elasticsearch/             # Elasticsearch configs
│   ├── index_template.json   # Index template
│   └── mappings.json         # Field mappings
│
├── kibana/                    # Kibana configurations
│   └── dashboard_export.json # Dashboard saved objects
│
├── webapp/                    # Flask frontend
│   ├── app.py                # Flask application
│   ├── templates/            # HTML templates
│   │   ├── index.html        # Dashboard page
│   │   └── alerts.html       # Alerts page
│   └── static/               # Static files (CSS, JS)
│
├── config/                    # Configuration files
│   ├── config.yaml           # Main configuration
│   └── detection_config.yaml # Detection thresholds
│
├── docker-compose.yml         # Docker Compose setup
├── requirements.txt           # Python dependencies
└── README.md                  # This file
```

## 🔧 Prerequisites

- **Python 3.8+**
- **Elasticsearch 7.x or 8.x**
- **Kibana 7.x or 8.x**
- **Docker & Docker Compose** (optional, for easy setup)
- **pip** (Python package manager)

## 📦 Installation

### Option 1: Docker Compose (Recommended)

```bash
# Clone or navigate to project directory
cd "C:\Project\Mini SIEM"

# Start Elasticsearch and Kibana
docker-compose up -d

# Wait for services to be ready (about 1-2 minutes)
# Check status: docker-compose ps
```

### Option 2: Manual Installation

```bash
# Install Python dependencies
pip install -r requirements.txt

# Ensure Elasticsearch and Kibana are running
# Elasticsearch: http://localhost:9200
# Kibana: http://localhost:5601
```

## 🚀 Usage

### Step 1: Generate Sample Logs

```bash
# Generate sample logs with security events
python simulators/brute_force_sim.py
python simulators/port_scan_sim.py
python simulators/failed_login_sim.py
```

### Step 2: Parse and Index Logs

```bash
# Parse logs and send to Elasticsearch
python scripts/log_parser.py --input logs/ --output es
```

### Step 3: Run Detection Engine

```bash
# Run detection rules and generate alerts
python scripts/event_detector.py
```

### Step 4: Start Flask Dashboard (Optional)

```bash
# Start Flask web application
cd webapp
python app.py
# Access at http://localhost:5000
```

### Step 5: Access Kibana Dashboard

1. Open Kibana: http://localhost:5601
2. Navigate to **Discover** to view logs
3. Import dashboard from `kibana/dashboard_export.json`
4. Navigate to **Dashboard** to view visualizations

## 🔍 Detection Rules

### Rule 1: Brute Force Detection
- **Trigger**: 5+ failed login attempts from same IP within 5 minutes
- **Severity**: High
- **MITRE ATT&CK**: T1110 - Brute Force

### Rule 2: Abnormal Login Pattern
- **Trigger**: Login outside business hours (e.g., 2 AM) from new IP
- **Severity**: Medium
- **MITRE ATT&CK**: T1078 - Valid Accounts

### Rule 3: Suspicious IP Behavior
- **Trigger**: IP with 10+ failed attempts across multiple users
- **Severity**: High
- **MITRE ATT&CK**: T1071 - Application Layer Protocol

### Rule 4: Port Scanning Activity
- **Trigger**: Multiple connection attempts to different ports from same IP
- **Severity**: Medium
- **MITRE ATT&CK**: T1046 - Network Service Scanning

### Rule 5: Multiple Failed Logins (Single User)
- **Trigger**: 3+ failed login attempts for same username within 1 minute
- **Severity**: Medium
- **MITRE ATT&CK**: T1110.001 - Password Guessing

## 🎯 MITRE ATT&CK Mapping

Each detected security event is mapped to MITRE ATT&CK framework techniques:

| Alert Type | MITRE ATT&CK Technique | Description |
|------------|------------------------|-------------|
| Brute Force Attack | T1110 - Brute Force | Adversary attempts multiple authentication attempts |
| Abnormal Login | T1078 - Valid Accounts | Unusual login pattern or timing |
| Port Scanning | T1046 - Network Service Scanning | Adversary scans network for open ports |
| Password Guessing | T1110.001 - Password Guessing | Multiple failed password attempts |
| Suspicious IP | T1071 - Application Layer Protocol | Unusual network behavior from IP |

## 📊 SOC Workflow

### Alert Classification

1. **High Severity** (Immediate Response Required)
   - Active brute force attacks
   - Suspicious IP with 10+ failed attempts
   - Critical system access attempts

2. **Medium Severity** (Investigate Within Hours)
   - Abnormal login patterns
   - Port scanning activity
   - Multiple failed logins for single user

3. **Low Severity** (Monitor and Review)
   - Single failed login attempts
   - Normal business hours login anomalies
   - First-time IP access

### SOC Analyst Workflow

```
1. Alert Generation
   ↓
2. Alert Classification (Auto)
   ↓
3. Triage & Investigation
   ├── Review alert details
   ├── Check MITRE ATT&CK mapping
   ├── Analyze IP reputation
   └── Review historical activity
   ↓
4. Response Actions
   ├── High: Immediate blocking/IP ban
   ├── Medium: Enhanced monitoring
   └── Low: Log for review
   ↓
5. Documentation & Reporting
```

## 📸 Screenshots

### Dashboard Views

*Note: Add screenshots here after running the system*

1. **Kibana Dashboard**: Security events visualization
2. **Flask Alert Dashboard**: Alert summary and details
3. **Detection Rules**: Active detection rules status
4. **MITRE ATT&CK Mapping**: Technique mappings for alerts

## 🛠️ Configuration

Edit `config/config.yaml` to customize:

- Elasticsearch connection settings
- Detection rule thresholds
- Log file paths
- Alert severity classifications

Edit `config/detection_config.yaml` to adjust:

- Failed login attempt thresholds
- Time windows for detection
- IP reputation checks
- Business hours definitions

## 📝 Log Format Examples

### Authentication Log
```
Jan 15 10:30:45 server sshd[12345]: Failed password for invalid user admin from 192.168.1.100 port 54321 ssh2
Jan 15 10:30:50 server sshd[12346]: Accepted publickey for user1 from 10.0.0.5 port 54322 ssh2
```

### System Log
```
Jan 15 10:35:12 server kernel: [123456.789] Connection attempt from 192.168.1.100:54321 to 22
Jan 15 10:35:15 server systemd: Started SSH service
```

## 🔒 Security Considerations

- **Data Privacy**: Ensure log data is handled according to your organization's privacy policies
- **Access Control**: Secure Elasticsearch and Kibana with authentication
- **Network Security**: Run on isolated network or VPN for production
- **Log Retention**: Configure appropriate log retention policies
- **Alert Thresholds**: Fine-tune detection rules to reduce false positives

## 🐛 Troubleshooting

### Elasticsearch Connection Issues
```bash
# Check Elasticsearch status
curl http://localhost:9200

# Check indices
curl http://localhost:9200/_cat/indices?v
```

### Log Parsing Errors
- Verify log file format matches expected format
- Check file permissions
- Review parser logs for specific errors

### Detection Rules Not Triggering
- Verify logs are indexed in Elasticsearch
- Check detection thresholds in config
- Review detection script logs

## 📚 Additional Resources

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Elasticsearch Documentation](https://www.elastic.co/guide/en/elasticsearch/reference/current/index.html)
- [Kibana User Guide](https://www.elastic.co/guide/en/kibana/current/index.html)

## 👥 Contributors

SOC Team - Mini SIEM Project

## 📄 License

This project is for educational and demonstration purposes.

---

**Note**: This is a mini SIEM for educational/demonstration purposes. For production environments, consider enterprise SIEM solutions with proper security controls, compliance features, and support.


