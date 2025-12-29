#!/usr/bin/env python3
"""
Log Collector
Collects logs from system and monitors for new entries
"""

import yaml
import time
import subprocess
from pathlib import Path
from datetime import datetime
import sys
import os

# Add scripts directory to path for imports
scripts_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, scripts_dir)

from log_parser import LogParser
from es_indexer import ESIndexer


class LogCollector:
    """Collect logs from system and index to Elasticsearch"""
    
    def __init__(self, config_path: str = "config/config.yaml"):
        """Initialize collector"""
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
        
        self.parser = LogParser(config_path)
        self.indexer = ESIndexer(config_path)
        self.log_paths = self.config['log_paths']
    
    def collect_auth_logs(self):
        """Collect authentication logs"""
        # In production, this would read from /var/log/auth.log
        # For this demo, we'll use the sample logs
        log_file = self.log_paths['auth_log']
        if Path(log_file).exists():
            events = self.parser.parse_auth_log(log_file)
            if events:
                self.indexer.index_events(events)
                print(f"Collected {len(events)} authentication events")
            return events
        return []
    
    def collect_ssh_logs(self):
        """Collect SSH logs"""
        log_file = self.log_paths['ssh_log']
        if Path(log_file).exists():
            events = self.parser.parse_ssh_log(log_file)
            if events:
                self.indexer.index_events(events)
                print(f"Collected {len(events)} SSH events")
            return events
        return []
    
    def collect_syslog(self):
        """Collect system logs"""
        log_file = self.log_paths['syslog']
        if Path(log_file).exists():
            events = self.parser.parse_syslog(log_file)
            if events:
                self.indexer.index_events(events)
                print(f"Collected {len(events)} system events")
            return events
        return []
    
    def collect_all(self):
        """Collect all log types"""
        print(f"Starting log collection at {datetime.now()}")
        
        all_events = []
        all_events.extend(self.collect_auth_logs())
        all_events.extend(self.collect_ssh_logs())
        all_events.extend(self.collect_syslog())
        
        print(f"Total events collected: {len(all_events)}")
        return all_events
    
    def monitor(self, interval_seconds: int = 60):
        """Monitor logs and collect new entries periodically"""
        print(f"Starting log monitoring (interval: {interval_seconds}s)")
        print("Press Ctrl+C to stop")
        
        try:
            while True:
                self.collect_all()
                time.sleep(interval_seconds)
        except KeyboardInterrupt:
            print("\nStopping log collector...")


def main():
    """Main function"""
    import argparse
    
    # Change to project root directory
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    os.chdir(project_root)
    
    parser = argparse.ArgumentParser(description='Collect logs for Mini SIEM')
    parser.add_argument('--monitor', '-m', action='store_true', 
                       help='Monitor logs continuously')
    parser.add_argument('--interval', '-i', type=int, default=60,
                       help='Monitoring interval in seconds')
    parser.add_argument('--config', '-c', default='config/config.yaml',
                       help='Config file path')
    
    args = parser.parse_args()
    
    collector = LogCollector(args.config)
    
    if args.monitor:
        collector.monitor(args.interval)
    else:
        collector.collect_all()


if __name__ == "__main__":
    main()

