# Mini SIEM + SOC Dashboard - Project Summary

## Project Overview

A complete, production-ready Mini SIEM (Security Information and Event Management) system with SOC (Security Operations Center) dashboard capabilities. This project demonstrates enterprise SIEM concepts in a simplified, educational implementation.

## ✅ Completed Deliverables

### 1. Log Collection & Parsing
- ✅ Sample log files (auth.log, ssh.log, syslog.log) with security events
- ✅ Python log parser with regex-based pattern matching
- ✅ Log normalization for Elasticsearch indexing
- ✅ Support for multiple log formats (authentication, SSH, system logs)

### 2. Log Storage
- ✅ Elasticsearch integration with proper index templates
- ✅ Field mappings for efficient querying
- ✅ Separate indices for logs and alerts
- ✅ Docker Compose setup for easy deployment

### 3. Security Event Detection
- ✅ 5 detection rules implemented:
  - Brute Force Attack Detection
  - Abnormal Login Pattern Detection
  - Suspicious IP Behavior Detection
  - Port Scanning Detection
  - Multiple Failed Login Detection
- ✅ Configurable detection thresholds
- ✅ Time-window based analysis
- ✅ Alert generation with metadata

### 4. Security Event Simulation
- ✅ Brute force attack simulator
- ✅ Port scanning simulator
- ✅ Failed login simulator
- ✅ Realistic log generation with timestamps

### 5. SOC Features
- ✅ MITRE ATT&CK framework mapping for all alerts
- ✅ Alert classification (Low/Medium/High severity)
- ✅ SOC-style alert descriptions with context
- ✅ Recommended actions for each alert type

### 6. Visualization Dashboards
- ✅ Kibana dashboard configuration and guide
- ✅ Flask web application for alert summary
- ✅ Real-time statistics and metrics
- ✅ Alert filtering and details view

### 7. Documentation
- ✅ Comprehensive README with architecture and usage
- ✅ Quick setup guide (SETUP.md)
- ✅ Detection logic explanation (DETECTION_LOGIC.md)
- ✅ Kibana dashboard setup guide
- ✅ Project structure documentation

## 📁 Project Structure

```
Mini SIEM/
├── config/                    # Configuration files
│   ├── config.yaml           # Main configuration
│   └── detection_config.yaml # Detection rule thresholds
├── detection/                 # Detection rules and mappings
│   ├── rules.py              # Rule definitions
│   └── mitre_mapping.json    # MITRE ATT&CK mappings
├── elasticsearch/             # Elasticsearch configs
│   ├── index_template.json   # Log index template
│   └── alert_template.json   # Alert index template
├── kibana/                    # Kibana configurations
│   ├── dashboard_export.json # Dashboard config
│   └── README.md             # Setup guide
├── logs/                      # Sample log files
│   ├── auth.log              # Authentication logs
│   ├── ssh.log               # SSH connection logs
│   └── syslog.log            # System logs
├── scripts/                   # Python scripts
│   ├── log_parser.py         # Log parsing engine
│   ├── log_collector.py      # Log collection script
│   ├── es_indexer.py         # Elasticsearch indexer
│   └── event_detector.py     # Detection engine
├── simulators/                # Event simulators
│   ├── brute_force_sim.py    # Brute force simulator
│   ├── port_scan_sim.py      # Port scan simulator
│   └── failed_login_sim.py   # Failed login simulator
├── webapp/                    # Flask frontend
│   ├── app.py                # Flask application
│   ├── templates/            # HTML templates
│   │   ├── index.html        # Dashboard
│   │   └── alerts.html       # Alerts page
│   └── static/               # Static files
├── docker-compose.yml         # Docker setup
├── requirements.txt           # Python dependencies
├── run_all.py                # Main execution script
├── README.md                  # Main documentation
├── SETUP.md                   # Quick setup guide
├── DETECTION_LOGIC.md         # Detection rules explanation
└── PROJECT_SUMMARY.md         # This file
```

## 🔧 Technology Stack

- **Backend**: Python 3.8+
- **Log Storage**: Elasticsearch 8.x
- **Visualization**: Kibana 8.x
- **Web Dashboard**: Flask 2.3+
- **Containerization**: Docker & Docker Compose

## 📊 Key Features

### Detection Capabilities
1. **Brute Force Detection**: 5+ failed attempts from same IP in 5 minutes
2. **Abnormal Login**: Logins outside business hours (08:00-18:00)
3. **Suspicious IP**: 10+ failed attempts across 3+ users in 15 minutes
4. **Port Scanning**: 5+ unique ports scanned in 10 minutes
5. **Multiple Failed Logins**: 3+ failed attempts for same user in 1 minute

### Dashboard Features
- Real-time alert statistics
- Failed vs successful login metrics
- Top attacking IPs
- Alert severity distribution
- Alert details with MITRE mapping
- Filterable alert views

### SOC Features
- MITRE ATT&CK technique mapping
- Alert severity classification
- Recommended actions per alert
- Alert status tracking
- Detailed alert descriptions

## 🚀 Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Start Elasticsearch & Kibana
docker-compose up -d

# 3. Generate sample logs
python simulators/brute_force_sim.py
python simulators/port_scan_sim.py
python simulators/failed_login_sim.py

# 4. Parse and index logs
python scripts/log_parser.py --input logs/ --output es

# 5. Run detection engine
python scripts/event_detector.py

# 6. Start Flask dashboard
cd webapp && python app.py

# 7. Access dashboards
# - Flask: http://localhost:5000
# - Kibana: http://localhost:5601
```

Or use the all-in-one script:
```bash
python run_all.py
```

## 📈 Detection Rules Summary

| Rule | Trigger | Severity | MITRE Technique |
|------|---------|----------|----------------|
| Brute Force | 5+ failed attempts from IP in 5 min | High | T1110 |
| Abnormal Login | Login outside business hours | Medium | T1078 |
| Suspicious IP | 10+ attempts across 3+ users in 15 min | High | T1071 |
| Port Scanning | 5+ unique ports in 10 min | Medium | T1046 |
| Multiple Failed Logins | 3+ failed attempts for user in 1 min | Medium | T1110.001 |

## 🎯 MITRE ATT&CK Mappings

All alerts are mapped to MITRE ATT&CK framework:

- **T1110** - Brute Force
- **T1110.001** - Password Guessing
- **T1078** - Valid Accounts
- **T1071** - Application Layer Protocol
- **T1046** - Network Service Scanning

## 📝 Configuration Files

### Main Configuration (`config/config.yaml`)
- Elasticsearch connection settings
- Log file paths
- Detection engine settings
- Flask server configuration

### Detection Configuration (`config/detection_config.yaml`)
- Detection rule thresholds
- Time windows
- Severity levels
- Business hours

## 🔒 Security Considerations

- Log data privacy handling
- Access control recommendations
- Network isolation suggestions
- Log retention policies
- Alert threshold tuning

## 📚 Documentation Files

1. **README.md**: Main project documentation with architecture and usage
2. **SETUP.md**: Quick setup guide for getting started
3. **DETECTION_LOGIC.md**: Detailed explanation of detection rules
4. **kibana/README.md**: Kibana dashboard setup instructions
5. **PROJECT_SUMMARY.md**: This summary document

## 🎓 Learning Outcomes

This project demonstrates:
- SIEM architecture and components
- Log parsing and normalization
- Security event detection rules
- Alert generation and classification
- MITRE ATT&CK framework mapping
- SOC workflows and practices
- Elasticsearch/Kibana integration
- Web dashboard development

## 🔄 Workflow

```
Log Collection → Parsing → Normalization → Elasticsearch
                                              ↓
                                         Detection Engine
                                              ↓
                                         Alert Generation
                                              ↓
                              ┌──────────────┴──────────────┐
                              ↓                             ↓
                        Flask Dashboard              Kibana Dashboard
```

## ✅ Testing Checklist

- [x] Log parsing works for all log types
- [x] Events indexed to Elasticsearch correctly
- [x] Detection rules trigger on simulated events
- [x] Alerts generated with proper metadata
- [x] Flask dashboard displays alerts
- [x] Kibana visualizations render correctly
- [x] MITRE mappings present in alerts
- [x] Configuration files load correctly

## 🚧 Future Enhancements (Not Implemented)

- Machine learning-based anomaly detection
- IP reputation checking integration
- Geographic anomaly detection
- User behavior analytics (UBA)
- Automated response actions
- Alert correlation engine
- Incident response workflows
- Threat intelligence integration

## 📄 License

This project is for educational and demonstration purposes.

## 👥 Author

SOC Team - Mini SIEM Project

---

**Note**: This is a mini SIEM for educational/demonstration purposes. For production environments, consider enterprise SIEM solutions with proper security controls, compliance features, and support.

