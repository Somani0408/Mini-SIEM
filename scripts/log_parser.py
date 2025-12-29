#!/usr/bin/env python3
"""
Mini SIEM Log Parser
Parses authentication, SSH, and system logs and normalizes them for Elasticsearch
"""

import re
import json
import yaml
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
import sys
import os
import argparse


class LogParser:
    """Parse and normalize log files for SIEM"""
    
    def __init__(self, config_path: str = "config/config.yaml"):
        """Initialize parser with configuration"""
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
        
        # Log patterns
        self.auth_patterns = {
            'ssh_failed': re.compile(
                r'(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+'
                r'(?P<hostname>\S+)\s+'
                r'sshd\[(?P<pid>\d+)\]:\s+'
                r'Failed password for (?:invalid user )?(?P<username>\S+) '
                r'from (?P<ip>\d+\.\d+\.\d+\.\d+) port (?P<port>\d+)'
            ),
            'ssh_accepted': re.compile(
                r'(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+'
                r'(?P<hostname>\S+)\s+'
                r'sshd\[(?P<pid>\d+)\]:\s+'
                r'Accepted (?:password|publickey) for (?P<username>\S+) '
                r'from (?P<ip>\d+\.\d+\.\d+\.\d+) port (?P<port>\d+)'
            ),
            'ssh_disconnect': re.compile(
                r'(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+'
                r'(?P<hostname>\S+)\s+'
                r'sshd\[(?P<pid>\d+)\]:\s+'
                r'Disconnected from (?P<ip>\d+\.\d+\.\d+\.\d+) port (?P<port>\d+)'
            )
        }
        
        self.ssh_pattern = re.compile(
            r'(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+'
            r'(?P<hostname>\S+)\s+'
            r'sshd\[(?P<pid>\d+)\]:\s+'
            r'Connection from (?P<ip>\d+\.\d+\.\d+\.\d+) port (?P<port>\d+)'
        )
        
        self.syslog_pattern = re.compile(
            r'(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+'
            r'(?P<hostname>\S+)\s+'
            r'(?P<service>\S+)(?:\[(?P<pid>\d+)\])?:\s+'
            r'(?P<message>.*)'
        )
        
        self.connection_pattern = re.compile(
            r'Connection attempt from (?P<ip>\d+\.\d+\.\d+\.\d+):(?P<src_port>\d+) to (?P<dst_port>\d+)'
        )
    
    def parse_timestamp(self, timestamp_str: str, year: int = None) -> datetime:
        """Parse log timestamp to datetime object"""
        if year is None:
            year = datetime.now().year
        
        # Format: Jan 15 10:30:45
        try:
            dt = datetime.strptime(f"{timestamp_str} {year}", "%b %d %H:%M:%S %Y")
            return dt
        except ValueError:
            # Fallback to current time if parsing fails
            return datetime.now()
    
    def parse_auth_log(self, log_file: str) -> List[Dict]:
        """Parse authentication log file"""
        events = []
        
        with open(log_file, 'r') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                
                # Try SSH failed pattern
                match = self.auth_patterns['ssh_failed'].search(line)
                if match:
                    event = {
                        '@timestamp': self.parse_timestamp(match.group('timestamp')).isoformat(),
                        'log_type': 'authentication',
                        'event_type': 'ssh_failed',
                        'hostname': match.group('hostname'),
                        'pid': int(match.group('pid')),
                        'username': match.group('username'),
                        'source_ip': match.group('ip'),
                        'source_port': int(match.group('port')),
                        'message': line,
                        'success': False
                    }
                    events.append(event)
                    continue
                
                # Try SSH accepted pattern
                match = self.auth_patterns['ssh_accepted'].search(line)
                if match:
                    auth_method = 'publickey' if 'publickey' in line else 'password'
                    event = {
                        '@timestamp': self.parse_timestamp(match.group('timestamp')).isoformat(),
                        'log_type': 'authentication',
                        'event_type': 'ssh_accepted',
                        'hostname': match.group('hostname'),
                        'pid': int(match.group('pid')),
                        'username': match.group('username'),
                        'source_ip': match.group('ip'),
                        'source_port': int(match.group('port')),
                        'auth_method': auth_method,
                        'message': line,
                        'success': True
                    }
                    events.append(event)
                    continue
                
                # Try SSH disconnect pattern
                match = self.auth_patterns['ssh_disconnect'].search(line)
                if match:
                    event = {
                        '@timestamp': self.parse_timestamp(match.group('timestamp')).isoformat(),
                        'log_type': 'authentication',
                        'event_type': 'ssh_disconnect',
                        'hostname': match.group('hostname'),
                        'pid': int(match.group('pid')),
                        'source_ip': match.group('ip'),
                        'source_port': int(match.group('port')),
                        'message': line
                    }
                    events.append(event)
        
        return events
    
    def parse_ssh_log(self, log_file: str) -> List[Dict]:
        """Parse SSH connection log file"""
        events = []
        
        with open(log_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                
                match = self.ssh_pattern.search(line)
                if match:
                    event = {
                        '@timestamp': self.parse_timestamp(match.group('timestamp')).isoformat(),
                        'log_type': 'ssh',
                        'event_type': 'connection',
                        'hostname': match.group('hostname'),
                        'pid': int(match.group('pid')),
                        'source_ip': match.group('ip'),
                        'source_port': int(match.group('port')),
                        'message': line
                    }
                    events.append(event)
        
        return events
    
    def parse_syslog(self, log_file: str) -> List[Dict]:
        """Parse system log file"""
        events = []
        
        with open(log_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                
                match = self.syslog_pattern.search(line)
                if match:
                    event = {
                        '@timestamp': self.parse_timestamp(match.group('timestamp')).isoformat(),
                        'log_type': 'system',
                        'hostname': match.group('hostname'),
                        'service': match.group('service'),
                        'pid': int(match.group('pid')) if match.group('pid') else None,
                        'message': match.group('message'),
                        'raw_message': line
                    }
                    
                    # Check for connection attempts
                    conn_match = self.connection_pattern.search(match.group('message'))
                    if conn_match:
                        event['event_type'] = 'connection_attempt'
                        event['source_ip'] = conn_match.group('ip')
                        event['source_port'] = int(conn_match.group('src_port'))
                        event['destination_port'] = int(conn_match.group('dst_port'))
                    else:
                        event['event_type'] = 'system_event'
                    
                    events.append(event)
        
        return events
    
    def normalize_event(self, event: Dict) -> Dict:
        """Normalize event for Elasticsearch indexing"""
        normalized = {
            '@timestamp': event.get('@timestamp', datetime.now().isoformat()),
            'log_type': event.get('log_type', 'unknown'),
            'event_type': event.get('event_type', 'unknown'),
            'hostname': event.get('hostname', 'unknown'),
            'source_ip': event.get('source_ip'),
            'message': event.get('message', '')
        }
        
        # Add optional fields if present
        optional_fields = [
            'username', 'source_port', 'destination_port', 'success',
            'auth_method', 'service', 'pid'
        ]
        
        for field in optional_fields:
            if field in event and event[field] is not None:
                normalized[field] = event[field]
        
        return normalized
    
    def parse_all_logs(self, log_dir: str = "logs") -> List[Dict]:
        """Parse all log files in directory"""
        log_dir_path = Path(log_dir)
        all_events = []
        
        # Parse authentication log
        auth_log = log_dir_path / "auth.log"
        if auth_log.exists():
            print(f"Parsing {auth_log}...")
            events = self.parse_auth_log(str(auth_log))
            all_events.extend(events)
            print(f"  Found {len(events)} authentication events")
        
        # Parse SSH log
        ssh_log = log_dir_path / "ssh.log"
        if ssh_log.exists():
            print(f"Parsing {ssh_log}...")
            events = self.parse_ssh_log(str(ssh_log))
            all_events.extend(events)
            print(f"  Found {len(events)} SSH events")
        
        # Parse syslog
        syslog = log_dir_path / "syslog.log"
        if syslog.exists():
            print(f"Parsing {syslog}...")
            events = self.parse_syslog(str(syslog))
            all_events.extend(events)
            print(f"  Found {len(events)} system events")
        
        # Normalize all events
        normalized_events = [self.normalize_event(e) for e in all_events]
        
        return normalized_events
    
    def save_to_json(self, events: List[Dict], output_file: str):
        """Save parsed events to JSON file"""
        with open(output_file, 'w') as f:
            json.dump(events, f, indent=2)
        print(f"Saved {len(events)} events to {output_file}")


def main():
    # Change to project root directory
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    os.chdir(project_root)
    
    parser = argparse.ArgumentParser(description='Parse logs for Mini SIEM')
    parser.add_argument('--input', '-i', default='logs', help='Input log directory')
    parser.add_argument('--output', '-o', default='parsed_logs.json', help='Output JSON file')
    parser.add_argument('--config', '-c', default='config/config.yaml', help='Config file path')
    parser.add_argument('--es', action='store_true', help='Send directly to Elasticsearch')
    
    args = parser.parse_args()
    
    # Parse logs
    log_parser = LogParser(args.config)
    events = log_parser.parse_all_logs(args.input)
    
    if args.es:
        # Send to Elasticsearch
        try:
            # Add scripts directory to path for imports
            scripts_dir = os.path.dirname(os.path.abspath(__file__))
            sys.path.insert(0, scripts_dir)
            from es_indexer import ESIndexer
            indexer = ESIndexer(args.config)
            indexer.index_events(events)
            print(f"Indexed {len(events)} events to Elasticsearch")
        except ImportError:
            print("Error: es_indexer module not found. Install dependencies: pip install -r requirements.txt")
            sys.exit(1)
        except Exception as e:
            print(f"Error indexing to Elasticsearch: {e}")
            sys.exit(1)
    else:
        # Save to JSON
        log_parser.save_to_json(events, args.output)
    
    print(f"\nTotal events parsed: {len(events)}")


if __name__ == "__main__":
    main()

