#!/usr/bin/env python3
"""
Detection Rules Definition
Central location for all security detection rules
"""

from typing import Dict, List, Any
from datetime import datetime, timedelta


class DetectionRule:
    """Base class for detection rules"""
    
    def __init__(self, rule_id: str, name: str, description: str, 
                 severity: str, mitre_technique: str):
        self.rule_id = rule_id
        self.name = name
        self.description = description
        self.severity = severity
        self.mitre_technique = mitre_technique
        self.enabled = True
    
    def evaluate(self, events: List[Dict]) -> List[Dict]:
        """Evaluate rule against events and return alerts"""
        raise NotImplementedError


# Detection rules can be extended here
# For now, rules are implemented in event_detector.py

RULES_METADATA = {
    'brute_force': {
        'id': 'RULE-001',
        'name': 'Brute Force Attack Detection',
        'description': 'Detects repeated failed login attempts from the same IP address',
        'category': 'Authentication',
        'mitre_technique': 'T1110'
    },
    'abnormal_login': {
        'id': 'RULE-002',
        'name': 'Abnormal Login Pattern Detection',
        'description': 'Detects login attempts outside normal business hours',
        'category': 'Authentication',
        'mitre_technique': 'T1078'
    },
    'suspicious_ip': {
        'id': 'RULE-003',
        'name': 'Suspicious IP Behavior Detection',
        'description': 'Detects IP addresses with multiple failed attempts across different users',
        'category': 'Network',
        'mitre_technique': 'T1071'
    },
    'port_scanning': {
        'id': 'RULE-004',
        'name': 'Port Scanning Detection',
        'description': 'Detects connection attempts to multiple ports from the same source IP',
        'category': 'Network',
        'mitre_technique': 'T1046'
    },
    'multiple_failed_logins': {
        'id': 'RULE-005',
        'name': 'Multiple Failed Logins Detection',
        'description': 'Detects multiple failed login attempts for the same username',
        'category': 'Authentication',
        'mitre_technique': 'T1110.001'
    }
}


def get_rule_metadata(rule_name: str) -> Dict[str, Any]:
    """Get metadata for a detection rule"""
    return RULES_METADATA.get(rule_name, {})


def list_all_rules() -> List[Dict[str, Any]]:
    """List all available detection rules"""
    return list(RULES_METADATA.values())

