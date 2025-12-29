#!/usr/bin/env python3
"""
Port Scanning Simulator
Generates sample logs simulating port scanning activity
"""

from datetime import datetime, timedelta
from pathlib import Path


def generate_port_scan_logs(output_file: str = "../logs/syslog.log", append: bool = True):
    """Generate port scanning logs"""
    
    # Scanner IP
    scanner_ip = "203.0.113.200"
    
    # Common ports to scan
    ports = [80, 443, 3306, 8080, 3389, 5432, 27017, 6379, 9200, 5601, 22, 21, 25]
    
    # Base timestamp (recent)
    base_time = datetime.now() - timedelta(minutes=5)
    
    logs = []
    
    # Generate connection attempts to multiple ports (port scanning pattern)
    for i, port in enumerate(ports):
        timestamp = base_time + timedelta(seconds=i * 5)
        src_port = 54333 + i
        
        log_line = (
            f"{timestamp.strftime('%b %d %H:%M:%S')} server "
            f"kernel: [123463.{678 + i}] Connection attempt from "
            f"{scanner_ip}:{src_port} to {port}\n"
        )
        logs.append(log_line)
    
    # Write to file
    mode = 'a' if append else 'w'
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_path, mode) as f:
        f.writelines(logs)
    
    print(f"Generated {len(logs)} port scanning log entries to {output_file}")
    print(f"Scanner IP: {scanner_ip}")
    print(f"Ports scanned: {len(ports)} different ports")
    print(f"Pattern: Multiple connection attempts to different ports within short timeframe")


if __name__ == "__main__":
    generate_port_scan_logs()

