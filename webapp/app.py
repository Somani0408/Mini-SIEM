#!/usr/bin/env python3
"""
Flask Web Application for Mini SIEM Dashboard
Provides alert summary and SOC dashboard views
"""

from flask import Flask, render_template, jsonify
from flask_cors import CORS
import yaml
import sys
import os
from datetime import datetime, timedelta

# Add scripts directory to path for imports
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
scripts_dir = os.path.join(project_root, 'scripts')
sys.path.insert(0, scripts_dir)

from es_indexer import ESIndexer

app = Flask(__name__)
CORS(app)

# Load configuration
config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'config', 'config.yaml')
with open(config_path, 'r') as f:
    config = yaml.safe_load(f)

indexer = ESIndexer(config_path)


@app.route('/')
def index():
    """Main dashboard page"""
    return render_template('index.html')


@app.route('/alerts')
def alerts_page():
    """Alerts page"""
    return render_template('alerts.html')


@app.route('/api/alerts')
def get_alerts():
    """Get recent alerts from Elasticsearch"""
    try:
        alert_index = config['detection']['alert_index']
        
        # Query recent alerts (last 24 hours)
        time_threshold = (datetime.now() - timedelta(hours=24)).isoformat()
        
        query = {
            "query": {
                "range": {
                    "@timestamp": {
                        "gte": time_threshold
                    }
                }
            },
            "sort": [{"@timestamp": {"order": "desc"}}],
            "size": 100
        }
        
        alerts = indexer.search(query)
        
        return jsonify({
            'success': True,
            'alerts': alerts,
            'count': len(alerts)
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/alerts/stats')
def get_alert_stats():
    """Get alert statistics"""
    try:
        alert_index = config['detection']['alert_index']
        
        # Query all alerts from last 24 hours
        time_threshold = (datetime.now() - timedelta(hours=24)).isoformat()
        
        # Get alerts grouped by severity
        query = {
            "query": {
                "range": {
                    "@timestamp": {
                        "gte": time_threshold
                    }
                }
            },
            "size": 0,
            "aggs": {
                "by_severity": {
                    "terms": {
                        "field": "severity",
                        "size": 10
                    }
                },
                "by_type": {
                    "terms": {
                        "field": "alert_type",
                        "size": 10
                    }
                }
            }
        }
        
        try:
            # Extract size from query if present
            size = query.pop('size', 100)
            response = indexer.es.search(index=alert_index, body=query, size=size)
            
            severity_counts = {
                bucket['key']: bucket['doc_count']
                for bucket in response['aggregations']['by_severity']['buckets']
            }
            
            type_counts = {
                bucket['key']: bucket['doc_count']
                for bucket in response['aggregations']['by_type']['buckets']
            }
            
            total_alerts = response['hits']['total']['value'] if isinstance(response['hits']['total'], dict) else response['hits']['total']
            
            return jsonify({
                'success': True,
                'stats': {
                    'total': total_alerts,
                    'by_severity': severity_counts,
                    'by_type': type_counts
                }
            })
        except Exception as e:
            # If index doesn't exist or no data, return empty stats
            return jsonify({
                'success': True,
                'stats': {
                    'total': 0,
                    'by_severity': {},
                    'by_type': {}
                }
            })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/logs/stats')
def get_log_stats():
    """Get log statistics"""
    try:
        index_name = config['elasticsearch']['index_name']
        
        # Query logs from last 24 hours
        time_threshold = (datetime.now() - timedelta(hours=24)).isoformat()
        
        query = {
            "query": {
                "bool": {
                    "must": [
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": time_threshold
                                }
                            }
                        }
                    ]
                }
            },
            "size": 0,
            "aggs": {
                "by_log_type": {
                    "terms": {
                        "field": "log_type",
                        "size": 10
                    }
                },
                "successful_logins": {
                    "filter": {
                        "term": {"success": True}
                    }
                },
                "failed_logins": {
                    "filter": {
                        "term": {"success": False}
                    }
                },
                "top_ips": {
                    "terms": {
                        "field": "source_ip",
                        "size": 10
                    }
                }
            }
        }
        
        try:
            response = indexer.es.search(index=index_name, body=query, size=0)
            
            successful_count = response['aggregations']['successful_logins']['doc_count']
            failed_count = response['aggregations']['failed_logins']['doc_count']
            
            top_ips = [
                {'ip': bucket['key'], 'count': bucket['doc_count']}
                for bucket in response['aggregations']['top_ips']['buckets']
            ]
            
            total_logs = response['hits']['total']['value'] if isinstance(response['hits']['total'], dict) else response['hits']['total']
            
            return jsonify({
                'success': True,
                'stats': {
                    'total': total_logs,
                    'successful_logins': successful_count,
                    'failed_logins': failed_count,
                    'top_ips': top_ips
                }
            })
        except Exception as e:
            return jsonify({
                'success': True,
                'stats': {
                    'total': 0,
                    'successful_logins': 0,
                    'failed_logins': 0,
                    'top_ips': []
                }
            })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


if __name__ == '__main__':
    flask_config = config.get('flask', {})
    app.run(
        host=flask_config.get('host', '0.0.0.0'),
        port=flask_config.get('port', 5000),
        debug=flask_config.get('debug', False)
    )

