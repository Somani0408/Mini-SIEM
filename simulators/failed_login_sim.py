#!/usr/bin/env python3
"""
Failed Login Simulator
Generates sample logs simulating multiple failed login attempts
"""

import random
from datetime import datetime, timedelta
from pathlib import Path


def generate_failed_login_logs(output_file: str = "../logs/auth.log", append: bool = True):
    """Generate failed login logs"""
    
    # Attacker IPs
    attacker_ips = [
        "198.51.100.100",
        "203.0.113.50",
        "192.168.1.200"
    ]
    
    # Target users
    users = ["user2", "admin", "root", "user1"]
    
    # Base timestamp (recent)
    base_time = datetime.now() - timedelta(minutes=15)
    
    logs = []
    
    # Generate multiple failed login attempts for same user (password guessing pattern)
    target_user = random.choice(users)
    attacker_ip = random.choice(attacker_ips)
    
    for i in range(7):
        timestamp = base_time + timedelta(seconds=i * 6)
        port = 54332 + i
        
        log_line = (
            f"{timestamp.strftime('%b %d %H:%M:%S')} server "
            f"sshd[{12369 + i}]: Failed password for {target_user} "
            f"from {attacker_ip} port {port} ssh2\n"
        )
        logs.append(log_line)
    
    # Write to file
    mode = 'a' if append else 'w'
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_path, mode) as f:
        f.writelines(logs)
    
    print(f"Generated {len(logs)} failed login log entries to {output_file}")
    print(f"Target user: {target_user}")
    print(f"Attacker IP: {attacker_ip}")
    print(f"Pattern: Multiple failed login attempts for same user")


if __name__ == "__main__":
    generate_failed_login_logs()

