# Detection Logic Explanation

This document explains the detection rules implemented in the Mini SIEM system.

## Overview

The detection engine analyzes normalized log events stored in Elasticsearch and identifies security threats based on configurable rules. Each detection rule evaluates patterns and generates alerts with severity levels and MITRE ATT&CK mappings.

## Detection Rules

### 1. Brute Force Detection (RULE-001)

**Purpose**: Detect repeated failed login attempts from the same IP address, indicating a brute force attack.

**Logic**:
- Groups failed authentication events by source IP
- Counts failed attempts within a configurable time window (default: 5 minutes)
- Triggers alert when threshold is reached (default: 5 failed attempts)

**Configuration** (`config/detection_config.yaml`):
```yaml
brute_force:
  enabled: true
  failed_attempts_threshold: 5
  time_window_minutes: 5
  severity: High
  mitre_technique: T1110
```

**Alert Fields**:
- `alert_type`: "brute_force"
- `severity`: "High"
- `source_ip`: Attacker IP address
- `attempt_count`: Number of failed attempts detected
- `mitre_technique`: "T1110" (Brute Force)
- `recommended_action`: "Block IP address and investigate source"

**Example Scenario**:
```
09:16:10 - Failed login from 192.168.1.100
09:16:15 - Failed login from 192.168.1.100
09:16:20 - Failed login from 192.168.1.100
09:16:25 - Failed login from 192.168.1.100
09:16:30 - Failed login from 192.168.1.100
→ Alert: Brute force detected (5 attempts in 5 minutes)
```

---

### 2. Abnormal Login Pattern Detection (RULE-002)

**Purpose**: Detect login attempts outside normal business hours, which may indicate unauthorized access.

**Logic**:
- Identifies successful login events
- Checks if login time is outside configured business hours (default: 08:00-18:00)
- Generates alert for each abnormal login

**Configuration**:
```yaml
abnormal_login:
  enabled: true
  business_hours_start: 08:00
  business_hours_end: 18:00
  timezone: UTC
  severity: Medium
  mitre_technique: T1078
```

**Alert Fields**:
- `alert_type`: "abnormal_login"
- `severity`: "Medium"
- `username`: User account
- `source_ip`: Source IP address
- `login_time`: Timestamp of the login
- `mitre_technique`: "T1078" (Valid Accounts)

**Example Scenario**:
```
02:15:30 - Successful login for user3 from 203.0.113.75
→ Alert: Abnormal login detected (outside business hours 08:00-18:00)
```

---

### 3. Suspicious IP Behavior Detection (RULE-003)

**Purpose**: Identify IP addresses attempting to access multiple user accounts, indicating reconnaissance or credential stuffing attacks.

**Logic**:
- Groups failed authentication events by source IP
- Tracks unique usernames targeted by each IP
- Triggers alert when:
  - Total failed attempts exceed threshold (default: 10)
  - Number of unique users targeted exceeds threshold (default: 3)
  - All within time window (default: 15 minutes)

**Configuration**:
```yaml
suspicious_ip:
  enabled: true
  failed_attempts_threshold: 10
  unique_users_threshold: 3
  time_window_minutes: 15
  severity: High
  mitre_technique: T1071
```

**Alert Fields**:
- `alert_type`: "suspicious_ip"
- `severity`: "High"
- `source_ip`: Suspicious IP address
- `attempt_count`: Total failed attempts
- `unique_users`: Number of different users targeted
- `affected_users`: List of targeted usernames
- `mitre_technique`: "T1071" (Application Layer Protocol)

**Example Scenario**:
```
IP 192.168.1.100 attempts login for:
- admin (5 failed attempts)
- root (3 failed attempts)
- user1 (2 failed attempts)
→ Alert: Suspicious IP behavior (10 attempts across 3 users)
```

---

### 4. Port Scanning Detection (RULE-004)

**Purpose**: Detect systematic scanning of network ports, indicating reconnaissance activity.

**Logic**:
- Analyzes connection attempt events from syslog
- Groups attempts by source IP
- Tracks unique destination ports accessed
- Triggers alert when:
  - Number of unique ports exceeds threshold (default: 5)
  - All attempts within time window (default: 10 minutes)

**Configuration**:
```yaml
port_scanning:
  enabled: true
  unique_ports_threshold: 5
  time_window_minutes: 10
  severity: Medium
  mitre_technique: T1046
```

**Alert Fields**:
- `alert_type`: "port_scanning"
- `severity`: "Medium"
- `source_ip`: Scanning IP address
- `ports_scanned`: Number of unique ports
- `target_ports`: List of port numbers scanned
- `mitre_technique`: "T1046" (Network Service Scanning)

**Example Scenario**:
```
22:10:05 - Connection attempt to port 80
22:10:10 - Connection attempt to port 443
22:10:15 - Connection attempt to port 3306
22:10:20 - Connection attempt to port 8080
22:10:25 - Connection attempt to port 3389
→ Alert: Port scanning detected (5 ports in 10 minutes)
```

---

### 5. Multiple Failed Logins (Single User) (RULE-005)

**Purpose**: Detect password guessing attacks targeting specific user accounts.

**Logic**:
- Groups failed authentication events by username
- Counts failed attempts within short time window (default: 1 minute)
- Triggers alert when threshold is reached (default: 3 attempts)

**Configuration**:
```yaml
multiple_failed_logins:
  enabled: true
  failed_attempts_threshold: 3
  time_window_minutes: 1
  severity: Medium
  mitre_technique: T1110.001
```

**Alert Fields**:
- `alert_type`: "multiple_failed_logins"
- `severity`: "Medium"
- `username`: Targeted user account
- `attempt_count`: Number of failed attempts
- `source_ips`: List of source IP addresses
- `mitre_technique`: "T1110.001" (Password Guessing)

**Example Scenario**:
```
11:20:12 - Failed login for user1 from 203.0.113.50
11:20:18 - Failed login for user1 from 203.0.113.50
11:20:24 - Failed login for user1 from 203.0.113.50
→ Alert: Multiple failed logins for user1 (3 attempts in 1 minute)
```

---

## Detection Engine Workflow

```
1. Event Collection
   └─> Logs parsed and indexed to Elasticsearch

2. Event Retrieval
   └─> Get recent events (last 60 minutes) from Elasticsearch

3. Rule Evaluation
   ├─> Brute Force Detection
   ├─> Abnormal Login Detection
   ├─> Suspicious IP Detection
   ├─> Port Scanning Detection
   └─> Multiple Failed Logins Detection

4. Alert Generation
   ├─> Create alert document with:
   │   ├─> Alert metadata (type, severity, timestamp)
   │   ├─> Event details (IPs, usernames, counts)
   │   ├─> MITRE ATT&CK mapping
   │   └─> Recommended actions
   └─> Index alerts to Elasticsearch

5. Alert Storage
   └─> Alerts stored in 'siem-alerts' index
```

## MITRE ATT&CK Mapping

Each alert is mapped to MITRE ATT&CK framework techniques:

| Alert Type | MITRE Technique | Tactic | Description |
|------------|----------------|---------|-------------|
| Brute Force | T1110 | Credential Access | Multiple authentication attempts |
| Abnormal Login | T1078 | Defense Evasion | Unusual login pattern |
| Suspicious IP | T1071 | Command and Control | Unusual network behavior |
| Port Scanning | T1046 | Discovery | Network reconnaissance |
| Multiple Failed Logins | T1110.001 | Credential Access | Password guessing |

Mappings are stored in `detection/mitre_mapping.json` and include:
- Technique ID and name
- Primary tactic
- Technique description

## Alert Classification

Alerts are classified by severity based on potential impact:

### High Severity
- **Brute Force Attacks**: Active attack in progress
- **Suspicious IP Behavior**: Multiple accounts targeted

**Response**: Immediate blocking and investigation

### Medium Severity
- **Abnormal Login Patterns**: Unusual but not necessarily malicious
- **Port Scanning**: Reconnaissance activity
- **Multiple Failed Logins**: Potential password guessing

**Response**: Investigation within hours, enhanced monitoring

### Low Severity
- Single failed login attempts
- First-time access from new IPs
- Anomalies during business hours

**Response**: Log for review, monitor trends

## Tuning Detection Rules

Detection rules can be tuned by modifying `config/detection_config.yaml`:

1. **Adjust Thresholds**: Increase/decrease trigger values
2. **Modify Time Windows**: Change detection timeframes
3. **Enable/Disable Rules**: Turn rules on/off as needed
4. **Change Severity**: Adjust alert severity levels

## False Positive Reduction

To reduce false positives:

1. **Whitelist Trusted IPs**: Add trusted IPs to exclusion list
2. **Adjust Business Hours**: Configure accurate business hours
3. **Increase Thresholds**: Raise thresholds for noisy environments
4. **Time Window Tuning**: Adjust time windows based on traffic patterns
5. **User Behavior Analysis**: Track normal user patterns

## Performance Considerations

- Detection runs on recent events (last 60 minutes by default)
- Batch processing for efficiency
- Indexed fields for fast queries
- Configurable batch sizes for bulk operations

## Future Enhancements

- Machine learning-based anomaly detection
- IP reputation checking integration
- Geographic anomaly detection
- User behavior analytics (UBA)
- Automated response actions
- Alert correlation and grouping

