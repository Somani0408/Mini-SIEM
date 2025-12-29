#!/usr/bin/env python3
"""
Security Event Detector
Detects security events using defined rules and generates alerts
"""

import yaml
from datetime import datetime, timedelta
from typing import List, Dict, Optional
from collections import defaultdict
import json
import sys
import os

# Add scripts directory to path for imports
scripts_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, scripts_dir)

from es_indexer import ESIndexer


class EventDetector:
    """Detect security events and generate alerts"""
    
    def __init__(self, config_path: str = "config/config.yaml", 
                 detection_config_path: str = "config/detection_config.yaml"):
        """Initialize detector with configurations"""
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
        
        with open(detection_config_path, 'r') as f:
            self.detection_config = yaml.safe_load(f)
        
        self.indexer = ESIndexer(config_path)
        self.alert_index = self.config['detection']['alert_index']
        
        # Load MITRE mappings
        self.mitre_mappings = self._load_mitre_mappings()
    
    def _load_mitre_mappings(self) -> Dict:
        """Load MITRE ATT&CK mappings"""
        # Get project root directory
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        mitre_file = os.path.join(project_root, "detection", "mitre_mapping.json")
        if os.path.exists(mitre_file):
            with open(mitre_file, 'r') as f:
                return json.load(f)
        return {}
    
    def get_recent_events(self, minutes: int = 60) -> List[Dict]:
        """Get recent events from Elasticsearch"""
        time_threshold = (datetime.now() - timedelta(minutes=minutes)).isoformat()
        
        query = {
            "query": {
                "range": {
                    "@timestamp": {
                        "gte": time_threshold
                    }
                }
            },
            "sort": [{"@timestamp": {"order": "asc"}}],
            "size": 10000
        }
        
        return self.indexer.search(query)
    
    def detect_brute_force(self, events: List[Dict]) -> List[Dict]:
        """Detect brute force attacks"""
        rule_config = self.detection_config['brute_force']
        if not rule_config.get('enabled', True):
            return []
        
        alerts = []
        time_window = timedelta(minutes=rule_config['time_window_minutes'])
        threshold = rule_config['failed_attempts_threshold']
        
        # Group failed attempts by IP
        ip_attempts = defaultdict(list)
        
        for event in events:
            if (event.get('event_type') == 'ssh_failed' and 
                event.get('source_ip') and 
                event.get('success') == False):
                ip = event['source_ip']
                timestamp = datetime.fromisoformat(event['@timestamp'].replace('Z', '+00:00'))
                ip_attempts[ip].append(timestamp)
        
        # Check for brute force patterns
        for ip, timestamps in ip_attempts.items():
            # Count attempts within time window
            recent_attempts = []
            for ts in sorted(timestamps):
                if not recent_attempts:
                    recent_attempts.append(ts)
                else:
                    # Remove attempts outside time window
                    recent_attempts = [t for t in recent_attempts 
                                     if ts - t <= time_window]
                    recent_attempts.append(ts)
                    
                    if len(recent_attempts) >= threshold:
                        # Brute force detected
                        alert = {
                            '@timestamp': datetime.now().isoformat(),
                            'alert_type': 'brute_force',
                            'severity': rule_config['severity'],
                            'title': f'Brute Force Attack Detected from {ip}',
                            'description': f'Detected {len(recent_attempts)} failed login attempts from {ip} within {rule_config["time_window_minutes"]} minutes',
                            'source_ip': ip,
                            'attempt_count': len(recent_attempts),
                            'time_window_minutes': rule_config['time_window_minutes'],
                            'mitre_technique': rule_config['mitre_technique'],
                            'mitre_tactic': self.mitre_mappings.get(rule_config['mitre_technique'], {}).get('tactic', 'Initial Access'),
                            'mitre_description': self.mitre_mappings.get(rule_config['mitre_technique'], {}).get('description', ''),
                            'status': 'new',
                            'recommended_action': 'Block IP address and investigate source'
                        }
                        alerts.append(alert)
        
        return alerts
    
    def detect_abnormal_login(self, events: List[Dict]) -> List[Dict]:
        """Detect abnormal login patterns (e.g., outside business hours)"""
        rule_config = self.detection_config['abnormal_login']
        if not rule_config.get('enabled', True):
            return []
        
        alerts = []
        business_start = rule_config['business_hours_start']
        business_end = rule_config['business_hours_end']
        
        start_hour, start_min = map(int, business_start.split(':'))
        end_hour, end_min = map(int, business_end.split(':'))
        
        for event in events:
            if event.get('event_type') == 'ssh_accepted' and event.get('success'):
                timestamp = datetime.fromisoformat(event['@timestamp'].replace('Z', '+00:00'))
                event_hour = timestamp.hour
                event_min = timestamp.minute
                
                # Check if outside business hours
                is_business_hours = (
                    (event_hour > start_hour or 
                     (event_hour == start_hour and event_min >= start_min)) and
                    (event_hour < end_hour or 
                     (event_hour == end_hour and event_min <= end_min))
                )
                
                if not is_business_hours:
                    alert = {
                        '@timestamp': datetime.now().isoformat(),
                        'alert_type': 'abnormal_login',
                        'severity': rule_config['severity'],
                        'title': f'Abnormal Login Time Detected for {event.get("username", "unknown")}',
                        'description': f'Login detected outside business hours ({business_start}-{business_end}) at {timestamp.strftime("%H:%M:%S")} from {event.get("source_ip", "unknown")}',
                        'source_ip': event.get('source_ip'),
                        'username': event.get('username'),
                        'login_time': timestamp.isoformat(),
                        'mitre_technique': rule_config['mitre_technique'],
                        'mitre_tactic': self.mitre_mappings.get(rule_config['mitre_technique'], {}).get('tactic', 'Defense Evasion'),
                        'mitre_description': self.mitre_mappings.get(rule_config['mitre_technique'], {}).get('description', ''),
                        'status': 'new',
                        'recommended_action': 'Verify user identity and review recent activity'
                    }
                    alerts.append(alert)
        
        return alerts
    
    def detect_suspicious_ip(self, events: List[Dict]) -> List[Dict]:
        """Detect suspicious IP behavior (multiple failed attempts across users)"""
        rule_config = self.detection_config['suspicious_ip']
        if not rule_config.get('enabled', True):
            return []
        
        alerts = []
        time_window = timedelta(minutes=rule_config['time_window_minutes'])
        threshold = rule_config['failed_attempts_threshold']
        user_threshold = rule_config['unique_users_threshold']
        
        # Group failed attempts by IP
        ip_activity = defaultdict(lambda: {'attempts': [], 'users': set()})
        
        for event in events:
            if (event.get('event_type') == 'ssh_failed' and 
                event.get('source_ip') and 
                event.get('success') == False):
                ip = event['source_ip']
                timestamp = datetime.fromisoformat(event['@timestamp'].replace('Z', '+00:00'))
                username = event.get('username', 'unknown')
                
                ip_activity[ip]['attempts'].append(timestamp)
                ip_activity[ip]['users'].add(username)
        
        # Check for suspicious patterns
        for ip, activity in ip_activity.items():
            attempts = sorted(activity['attempts'])
            users = activity['users']
            
            # Count recent attempts
            recent_attempts = []
            for ts in attempts:
                if not recent_attempts:
                    recent_attempts.append(ts)
                else:
                    recent_attempts = [t for t in recent_attempts 
                                     if ts - t <= time_window]
                    recent_attempts.append(ts)
            
            if (len(recent_attempts) >= threshold and 
                len(users) >= user_threshold):
                alert = {
                    '@timestamp': datetime.now().isoformat(),
                    'alert_type': 'suspicious_ip',
                    'severity': rule_config['severity'],
                    'title': f'Suspicious IP Activity Detected: {ip}',
                    'description': f'IP {ip} has {len(recent_attempts)} failed login attempts across {len(users)} different users within {rule_config["time_window_minutes"]} minutes',
                    'source_ip': ip,
                    'attempt_count': len(recent_attempts),
                    'unique_users': len(users),
                    'affected_users': list(users),
                    'mitre_technique': rule_config['mitre_technique'],
                    'mitre_tactic': self.mitre_mappings.get(rule_config['mitre_technique'], {}).get('tactic', 'Discovery'),
                    'mitre_description': self.mitre_mappings.get(rule_config['mitre_technique'], {}).get('description', ''),
                    'status': 'new',
                    'recommended_action': 'Immediately block IP and investigate all affected accounts'
                }
                alerts.append(alert)
        
        return alerts
    
    def detect_port_scanning(self, events: List[Dict]) -> List[Dict]:
        """Detect port scanning activity"""
        rule_config = self.detection_config['port_scanning']
        if not rule_config.get('enabled', True):
            return []
        
        alerts = []
        time_window = timedelta(minutes=rule_config['time_window_minutes'])
        threshold = rule_config['unique_ports_threshold']
        
        # Group connection attempts by IP
        ip_ports = defaultdict(lambda: {'ports': set(), 'timestamps': []})
        
        for event in events:
            if (event.get('event_type') == 'connection_attempt' and 
                event.get('source_ip') and 
                event.get('destination_port')):
                ip = event['source_ip']
                port = event['destination_port']
                timestamp = datetime.fromisoformat(event['@timestamp'].replace('Z', '+00:00'))
                
                ip_ports[ip]['ports'].add(port)
                ip_ports[ip]['timestamps'].append(timestamp)
        
        # Check for port scanning patterns
        for ip, data in ip_ports.items():
            ports = data['ports']
            timestamps = sorted(data['timestamps'])
            
            # Check if ports scanned within time window
            if len(timestamps) > 1:
                time_span = timestamps[-1] - timestamps[0]
                if time_span <= time_window and len(ports) >= threshold:
                    alert = {
                        '@timestamp': datetime.now().isoformat(),
                        'alert_type': 'port_scanning',
                        'severity': rule_config['severity'],
                        'title': f'Port Scanning Activity Detected from {ip}',
                        'description': f'IP {ip} attempted connections to {len(ports)} different ports within {rule_config["time_window_minutes"]} minutes',
                        'source_ip': ip,
                        'ports_scanned': len(ports),
                        'target_ports': sorted(list(ports)),
                        'mitre_technique': rule_config['mitre_technique'],
                        'mitre_tactic': self.mitre_mappings.get(rule_config['mitre_technique'], {}).get('tactic', 'Discovery'),
                        'mitre_description': self.mitre_mappings.get(rule_config['mitre_technique'], {}).get('description', ''),
                        'status': 'new',
                        'recommended_action': 'Block IP and review network firewall rules'
                    }
                    alerts.append(alert)
        
        return alerts
    
    def detect_multiple_failed_logins(self, events: List[Dict]) -> List[Dict]:
        """Detect multiple failed logins for same user"""
        rule_config = self.detection_config['multiple_failed_logins']
        if not rule_config.get('enabled', True):
            return []
        
        alerts = []
        time_window = timedelta(minutes=rule_config['time_window_minutes'])
        threshold = rule_config['failed_attempts_threshold']
        
        # Group failed attempts by username
        user_attempts = defaultdict(list)
        
        for event in events:
            if (event.get('event_type') == 'ssh_failed' and 
                event.get('username') and 
                event.get('success') == False):
                username = event['username']
                timestamp = datetime.fromisoformat(event['@timestamp'].replace('Z', '+00:00'))
                user_attempts[username].append({
                    'timestamp': timestamp,
                    'source_ip': event.get('source_ip')
                })
        
        # Check for multiple failed logins
        for username, attempts in user_attempts.items():
            sorted_attempts = sorted(attempts, key=lambda x: x['timestamp'])
            recent_attempts = []
            
            for attempt in sorted_attempts:
                if not recent_attempts:
                    recent_attempts.append(attempt)
                else:
                    # Remove attempts outside time window
                    recent_attempts = [a for a in recent_attempts 
                                     if attempt['timestamp'] - a['timestamp'] <= time_window]
                    recent_attempts.append(attempt)
                    
                    if len(recent_attempts) >= threshold:
                        alert = {
                            '@timestamp': datetime.now().isoformat(),
                            'alert_type': 'multiple_failed_logins',
                            'severity': rule_config['severity'],
                            'title': f'Multiple Failed Login Attempts for User: {username}',
                            'description': f'Detected {len(recent_attempts)} failed login attempts for user {username} within {rule_config["time_window_minutes"]} minute(s)',
                            'username': username,
                            'attempt_count': len(recent_attempts),
                            'source_ips': list(set([a['source_ip'] for a in recent_attempts if a['source_ip']])),
                            'mitre_technique': rule_config['mitre_technique'],
                            'mitre_tactic': self.mitre_mappings.get(rule_config['mitre_technique'], {}).get('tactic', 'Credential Access'),
                            'mitre_description': self.mitre_mappings.get(rule_config['mitre_technique'], {}).get('description', ''),
                            'status': 'new',
                            'recommended_action': 'Review account security and consider temporary lockout'
                        }
                        alerts.append(alert)
                        break  # One alert per user per detection
        
        return alerts
    
    def run_detection(self) -> List[Dict]:
        """Run all detection rules"""
        print("Running security event detection...")
        
        # Get recent events (last 60 minutes)
        events = self.get_recent_events(minutes=60)
        print(f"Analyzing {len(events)} recent events...")
        
        all_alerts = []
        
        # Run detection rules
        if self.detection_config['brute_force'].get('enabled', True):
            alerts = self.detect_brute_force(events)
            all_alerts.extend(alerts)
            print(f"  Brute force detection: {len(alerts)} alerts")
        
        if self.detection_config['abnormal_login'].get('enabled', True):
            alerts = self.detect_abnormal_login(events)
            all_alerts.extend(alerts)
            print(f"  Abnormal login detection: {len(alerts)} alerts")
        
        if self.detection_config['suspicious_ip'].get('enabled', True):
            alerts = self.detect_suspicious_ip(events)
            all_alerts.extend(alerts)
            print(f"  Suspicious IP detection: {len(alerts)} alerts")
        
        if self.detection_config['port_scanning'].get('enabled', True):
            alerts = self.detect_port_scanning(events)
            all_alerts.extend(alerts)
            print(f"  Port scanning detection: {len(alerts)} alerts")
        
        if self.detection_config['multiple_failed_logins'].get('enabled', True):
            alerts = self.detect_multiple_failed_logins(events)
            all_alerts.extend(alerts)
            print(f"  Multiple failed logins detection: {len(alerts)} alerts")
        
        # Index alerts to Elasticsearch
        if all_alerts:
            # Create alert index if it doesn't exist
            if not self.indexer.es.indices.exists(index=self.alert_index):
                self.indexer.es.indices.create(index=self.alert_index)
            
            self.indexer.index_events(all_alerts)
            print(f"\nTotal alerts generated: {len(all_alerts)}")
        
        return all_alerts


def main():
    """Main function"""
    detector = EventDetector()
    alerts = detector.run_detection()
    
    # Print alert summary
    if alerts:
        print("\n=== Alert Summary ===")
        for alert in alerts:
            print(f"\n[{alert['severity']}] {alert['title']}")
            print(f"  Type: {alert['alert_type']}")
            print(f"  MITRE: {alert['mitre_technique']} - {alert['mitre_tactic']}")
            print(f"  Action: {alert['recommended_action']}")
    else:
        print("\nNo security events detected.")


if __name__ == "__main__":
    main()

