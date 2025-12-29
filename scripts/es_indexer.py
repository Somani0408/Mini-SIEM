#!/usr/bin/env python3
"""
Elasticsearch Indexer
Indexes normalized log events to Elasticsearch
"""

import yaml
from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk
from typing import List, Dict
from datetime import datetime
import json


class ESIndexer:
    """Index events to Elasticsearch"""
    
    def __init__(self, config_path: str = "config/config.yaml"):
        """Initialize Elasticsearch connection"""
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
        
        es_config = self.config['elasticsearch']
        
        # Create Elasticsearch client
        self.es = Elasticsearch(
            [f"{es_config['host']}:{es_config['port']}"],
            use_ssl=es_config.get('use_ssl', False),
            verify_certs=es_config.get('verify_certs', False)
        )
        
        self.index_name = es_config['index_name']
        self.index_pattern = es_config.get('index_pattern', f"{self.index_name}-*")
        
        # Create index template if it doesn't exist
        self.create_index_template()
        
        # Ensure index exists
        if not self.es.indices.exists(index=self.index_name):
            self.es.indices.create(index=self.index_name)
            print(f"Created index: {self.index_name}")
    
    def create_index_template(self):
        """Create index template for proper field mapping"""
        template_name = f"{self.index_name}-template"
        
        template = {
            "index_patterns": [self.index_pattern],
            "settings": {
                "number_of_shards": 1,
                "number_of_replicas": 0
            },
            "mappings": {
                "properties": {
                    "@timestamp": {"type": "date"},
                    "log_type": {"type": "keyword"},
                    "event_type": {"type": "keyword"},
                    "hostname": {"type": "keyword"},
                    "source_ip": {"type": "ip"},
                    "username": {"type": "keyword"},
                    "source_port": {"type": "integer"},
                    "destination_port": {"type": "integer"},
                    "success": {"type": "boolean"},
                    "auth_method": {"type": "keyword"},
                    "service": {"type": "keyword"},
                    "pid": {"type": "integer"},
                    "message": {"type": "text", "fields": {"keyword": {"type": "keyword"}}}
                }
            }
        }
        
        try:
            self.es.indices.put_index_template(name=template_name, body=template)
            print(f"Created index template: {template_name}")
        except Exception as e:
            # Template might already exist
            print(f"Template creation note: {e}")
    
    def index_event(self, event: Dict) -> bool:
        """Index a single event"""
        try:
            result = self.es.index(
                index=self.index_name,
                document=event
            )
            return result.get('result') in ['created', 'updated']
        except Exception as e:
            print(f"Error indexing event: {e}")
            return False
    
    def index_events(self, events: List[Dict], batch_size: int = 1000):
        """Index multiple events using bulk API"""
        actions = []
        
        for event in events:
            action = {
                "_index": self.index_name,
                "_source": event
            }
            actions.append(action)
        
        # Bulk index
        try:
            success, failed = bulk(self.es, actions, chunk_size=batch_size, raise_on_error=False)
            print(f"Successfully indexed: {success} events")
            if failed:
                print(f"Failed to index: {len(failed)} events")
                for fail in failed[:5]:  # Show first 5 failures
                    print(f"  Error: {fail}")
        except Exception as e:
            print(f"Bulk indexing error: {e}")
    
    def search(self, query: Dict) -> List[Dict]:
        """Search events in Elasticsearch"""
        try:
            # Extract size from query if present, otherwise use default
            # Make a copy to avoid modifying original query
            query_copy = query.copy()
            size = query_copy.pop('size', 100) if 'size' in query_copy else 100
            response = self.es.search(
                index=self.index_name,
                body=query_copy,
                size=size
            )
            return [hit['_source'] for hit in response['hits']['hits']]
        except Exception as e:
            print(f"Search error: {e}")
            return []
    
    def get_stats(self) -> Dict:
        """Get index statistics"""
        try:
            stats = self.es.indices.stats(index=self.index_name)
            return {
                'total_docs': stats['indices'][self.index_name]['total']['docs']['count'],
                'total_size': stats['indices'][self.index_name]['total']['store']['size_in_bytes']
            }
        except Exception as e:
            print(f"Error getting stats: {e}")
            return {}


def main():
    """Test indexer"""
    indexer = ESIndexer()
    
    # Test event
    test_event = {
        '@timestamp': datetime.now().isoformat(),
        'log_type': 'test',
        'event_type': 'test_event',
        'hostname': 'test-server',
        'message': 'Test event for Mini SIEM'
    }
    
    # Index test event
    if indexer.index_event(test_event):
        print("Test event indexed successfully")
    
    # Get stats
    stats = indexer.get_stats()
    print(f"Index stats: {stats}")


if __name__ == "__main__":
    main()

