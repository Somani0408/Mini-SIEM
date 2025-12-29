#!/usr/bin/env python3
"""
Main Script to Run All Components
Runs log collection, parsing, indexing, and detection in sequence
"""

import sys
import os
import time
from pathlib import Path

# Change to project root directory
project_root = os.path.dirname(os.path.abspath(__file__))
os.chdir(project_root)

# Add scripts directory to path
scripts_dir = os.path.join(project_root, 'scripts')
sys.path.insert(0, scripts_dir)

from log_collector import LogCollector
from event_detector import EventDetector


def main():
    """Run all SIEM components"""
    print("=" * 60)
    print("Mini SIEM - Starting All Components")
    print("=" * 60)
    
    # Step 1: Collect and index logs
    print("\n[1/3] Collecting and indexing logs...")
    try:
        collector = LogCollector()
        collector.collect_all()
        print("✓ Logs collected and indexed successfully")
    except Exception as e:
        print(f"✗ Error collecting logs: {e}")
        return
    
    # Wait a moment for indexing
    time.sleep(2)
    
    # Step 2: Run detection engine
    print("\n[2/3] Running security event detection...")
    try:
        detector = EventDetector()
        alerts = detector.run_detection()
        print(f"✓ Detection completed. Generated {len(alerts)} alerts")
    except Exception as e:
        print(f"✗ Error running detection: {e}")
        return
    
    # Step 3: Summary
    print("\n[3/3] Summary")
    print("=" * 60)
    print("\n✓ Mini SIEM is ready!")
    print("\nNext steps:")
    print("  1. View logs in Kibana: http://localhost:5601")
    print("  2. View alerts in Flask dashboard: http://localhost:5000")
    print("  3. Run 'python webapp/app.py' to start Flask dashboard")
    print("  4. Run 'python scripts/event_detector.py' to run detection again")
    print("\n" + "=" * 60)


if __name__ == "__main__":
    main()

