#!/usr/bin/env python3
"""
Brute Force Attack Simulator
Generates sample logs simulating brute force attacks
"""

import random
from datetime import datetime, timedelta
from pathlib import Path


def generate_brute_force_logs(output_file: str = "../logs/auth.log", append: bool = True):
    """Generate brute force attack logs"""
    
    # Attacker IP
    attacker_ip = "192.168.1.100"
    
    # Target usernames
    usernames = ["admin", "root", "user1", "administrator", "test"]
    
    # Base timestamp (recent)
    base_time = datetime.now() - timedelta(minutes=10)
    
    logs = []
    
    # Generate rapid failed login attempts (brute force pattern)
    for i in range(8):
        timestamp = base_time + timedelta(seconds=i * 5)
        username = random.choice(usernames)
        port = 54321 + i
        
        log_line = (
            f"{timestamp.strftime('%b %d %H:%M:%S')} server "
            f"sshd[{12345 + i}]: Failed password for invalid user {username} "
            f"from {attacker_ip} port {port} ssh2\n"
        )
        logs.append(log_line)
    
    # Write to file
    mode = 'a' if append else 'w'
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_path, mode) as f:
        f.writelines(logs)
    
    print(f"Generated {len(logs)} brute force log entries to {output_file}")
    print(f"Attacker IP: {attacker_ip}")
    print(f"Pattern: Rapid failed login attempts")


if __name__ == "__main__":
    generate_brute_force_logs()

