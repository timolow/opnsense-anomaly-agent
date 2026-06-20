#!/usr/bin/env python3
"""
Graylog/OpenSearch Training Data Extractor

Extracts historical firewall, HTTP, connection, and alert data from OpenSearch
and converts it to the format the agent uses for baseline learning.

Usage:
    python graylog_training_extractor.py --index "opnsense_filterlog-*" --output /tmp/training_data.jsonl
    python graylog_training_extractor.py --index "http-*" --output /tmp/http_training.jsonl
"""

import json
import logging
import argparse
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, List, Optional

try:
    from opensearchpy import OpenSearch
    ES_AVAILABLE = True
except ImportError:
    ES_AVAILABLE = False

logger = logging.getLogger(__name__)

# ── Configuration ──
DEFAULT_ES_HOSTS = [
    "http://192.168.1.32:9200",
    "http://192.168.1.33:9200", 
    "http://192.168.1.35:9200"
]
DEFAULT_ES_USER = "elastic"
DEFAULT_ES_PASSWORD="changeme"

# Index patterns by data type
INDEX_PATTERNS = {
    "firewall": "opnsense_filterlog-*",
    "http": "http-*",
    "connections": "conn-*",
    "alerts": "alert-*",
    "system": "graylog_*"
}

class GraylogTrainingExtractor:
    """Extracts training data from Graylog/OpenSearch."""
    
    def __init__(self, hosts: List[str] = None, user: str = DEFAULT_ES_USER, 
                 password: str = DEFAULT_ES_PASSWORD):
        if not ES_AVAILABLE:
            raise ImportError("opensearch-py package not installed. Run: pip install opensearch-py")
        
        self.hosts = hosts or DEFAULT_ES_HOSTS
        self.es = OpenSearch(
            hosts=self.hosts,
            http_auth=(user, password),
            verify_certs=False,
            retry_on_timeout=True,
            max_retries=3
        )
        self._connected = False
    
    def connect(self) -> bool:
        """Test connection to OpenSearch cluster."""
        try:
            info = self.es.info()
            version = info.get("version", {}).get("number", "unknown")
            logger.info(f"Connected to OpenSearch {version}")
            self._connected = True
            return True
        except Exception as e:
            logger.error(f"Failed to connect to OpenSearch: {e}")
            self._connected = False
            return False
    
    def extract_firewall_events(self, index_pattern: Optional[str] = None, 
                               start_time: Optional[str] = None, end_time: Optional[str] = None,
                               sample_size: int = 100000) -> List[Dict[str, Any]]:
        """Extract firewall events for training."""
        if not self.connect():
            return []
        
        index = index_pattern or INDEX_PATTERNS["firewall"]
        query = {
            "size": 10000,
            "_source": ["timestamp", "src_ip", "dst_ip", "src_port", "dst_port", 
                       "action", "rule_number", "interface", "protocol_name", "direction",
                       "dst_ip", "src_port"],
            "query": {
                "bool": {
                    "must": [
                        {"exists": {"field": "src_ip"}},
                        {"exists": {"field": "dst_ip"}}
                    ]
                }
            },
            "sort": [{"timestamp": {"order": "asc"}}]
        }
        
        if start_time:
            query["query"]["bool"]["filter"] = [
                {"range": {"timestamp": {"gte": start_time}}}
            ]
        if end_time:
            if "filter" not in query["query"]["bool"]:
                query["query"]["bool"]["filter"] = []
            query["query"]["bool"]["filter"].append(
                {"range": {"timestamp": {"lte": end_time}}}
            )
        
        events = []
        scroll_id = None
        total_extracted = 0
        
        try:
            # Initial search with scroll
            response = self.es.search(
                index=index,
                body=query,
                scroll="5m"
            )
            
            scroll_id = response.get('_scroll_id')
            hits = response['hits']['hits']
            
            while hits and total_extracted < sample_size:
                for hit in hits:
                    source = hit['_source']
                    # Convert to agent format
                    event = self._convert_firewall_event(source)
                    if event:
                        events.append(event)
                        total_extracted += 1
                    
                    if total_extracted >= sample_size:
                        break
                
                if not scroll_id or total_extracted >= sample_size:
                    break
                
                # Scroll to next batch
                response = self.es.scroll(
                    scroll_id=scroll_id,
                    scroll="5m"
                )
                scroll_id = response.get('_scroll_id')
                hits = response['hits']['hits']
                
        except Exception as e:
            logger.error(f"Error extracting firewall events: {e}")
        
        logger.info(f"Extracted {len(events)} firewall events")
        return events
    
    def extract_http_events(self, index_pattern: Optional[str] = None, sample_size: int = 50000) -> List[Dict[str, Any]]:
        """Extract HTTP events for training."""
        if not self.connect():
            return []
        
        index = index_pattern or INDEX_PATTERNS["http"]
        query = {
            "size": 10000,
            "_source": ["start_time", "ip_src_saddr", "ip_dst_saddr", "ip_src_port", 
                       "ip_dst_port", "method", "uri", "status_msg", "user_agent", "host"],
            "sort": [{"start_time": {"order": "asc"}}]
        }
        
        events = []
        scroll_id = None
        total_extracted = 0
        
        try:
            response = self.es.search(
                index=index,
                body=query,
                scroll="5m"
            )
            
            scroll_id = response.get('_scroll_id')
            hits = response['hits']['hits']
            
            while hits and total_extracted < sample_size:
                for hit in hits:
                    source = hit['_source']
                    event = self._convert_http_event(source)
                    if event:
                        events.append(event)
                        total_extracted += 1
                    
                    if total_extracted >= sample_size:
                        break
                
                if not scroll_id or total_extracted >= sample_size:
                    break
                
                response = self.es.scroll(
                    scroll_id=scroll_id,
                    scroll="5m"
                )
                scroll_id = response.get('_scroll_id')
                hits = response['hits']['hits']
                
        except Exception as e:
            logger.error(f"Error extracting HTTP events: {e}")
        
        logger.info(f"Extracted {len(events)} HTTP events")
        return events
    
    def extract_alerts(self, index_pattern: Optional[str] = None, sample_size: int = 25000) -> List[Dict[str, Any]]:
        """Extract alert events for training."""
        if not self.connect():
            return []
        
        index = index_pattern or INDEX_PATTERNS["alerts"]
        query = {
            "size": 10000,
            "_source": ["timestamp", "message", "source", "level", "facility"],
            "sort": [{"timestamp": {"order": "asc"}}]
        }
        
        events = []
        scroll_id = None
        total_extracted = 0
        
        try:
            response = self.es.search(
                index=index,
                body=query,
                scroll="5m"
            )
            
            scroll_id = response.get('_scroll_id')
            hits = response['hits']['hits']
            
            while hits and total_extracted < sample_size:
                for hit in hits:
                    source = hit['_source']
                    event = self._convert_alert_event(source)
                    if event:
                        events.append(event)
                        total_extracted += 1
                    
                    if total_extracted >= sample_size:
                        break
                
                if not scroll_id or total_extracted >= sample_size:
                    break
                
                response = self.es.scroll(
                    scroll_id=scroll_id,
                    scroll="5m"
                )
                scroll_id = response.get('_scroll_id')
                hits = response['hits']['hits']
                
        except Exception as e:
            logger.error(f"Error extracting alerts: {e}")
        
        logger.info(f"Extracted {len(events)} alert events")
        return events
    
    def _convert_firewall_event(self, source: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Convert OpenSearch firewall event to agent format."""
        try:
            return {
                "timestamp": source.get("timestamp"),
                "src_ip": source.get("src_ip"),
                "dst_ip": source.get("dst_ip"),
                "src_port": source.get("src_port"),
                "dst_port": source.get("dst_port"),
                "action": source.get("action"),
                "rule": source.get("rule_number"),
                "interface": source.get("interface"),
                "protocol": source.get("protocol_name"),
                "direction": source.get("direction"),
                "source": "firewall"
            }
        except Exception as e:
            logger.debug(f"Error converting firewall event: {e}")
            return None
    
    def _convert_http_event(self, source: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Convert OpenSearch HTTP event to agent format."""
        try:
            return {
                "timestamp": datetime.fromtimestamp(source.get("start_time", 0) / 1000, tz=timezone.utc).isoformat(),
                "src_ip": source.get("ip_src_saddr"),
                "dst_ip": source.get("ip_dst_saddr"),
                "src_port": source.get("ip_src_port"),
                "dst_port": source.get("ip_dst_port"),
                "method": source.get("method"),
                "path": source.get("uri"),
                "status_code": source.get("status_msg"),
                "user_agent": source.get("user_agent"),
                "host": source.get("host"),
                "source": "http"
            }
        except Exception as e:
            logger.debug(f"Error converting HTTP event: {e}")
            return None
    
    def _convert_alert_event(self, source: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Convert OpenSearch alert event to agent format."""
        try:
            return {
                "timestamp": source.get("timestamp"),
                "message": source.get("message"),
                "source_host": source.get("source"),
                "level": source.get("level"),
                "facility": source.get("facility"),
                "source": "alert"
            }
        except Exception as e:
            logger.debug(f"Error converting alert event: {e}")
            return None
    
    def get_cluster_stats(self) -> Dict[str, Any]:
        """Get cluster statistics."""
        if not self.connect():
            return {}
        
        try:
            # Get index stats
            indices = self.es.indices.get(index="*")
            stats = {
                "total_indices": len(indices),
                "indices": {}
            }
            
            for index_name in list(indices.keys())[:20]:  # Limit to first 20
                index_stats = self.es.indices.stats(index=index_name)
                for idx in index_stats['indices']:
                    docs = idx['primaries']['docs']
                    store = idx['primaries']['store']
                    stats['indices'][index_name] = {
                        "docs_count": docs.get('count', 0),
                        "store_size_mb": store.get('size_in_bytes', 0) / (1024 * 1024)
                    }
            
            return stats
        except Exception as e:
            logger.error(f"Error getting cluster stats: {e}")
            return {}

def main():
    parser = argparse.ArgumentParser(description="Graylog/OpenSearch Training Data Extractor")
    parser.add_argument("--hosts", nargs="+", default=DEFAULT_ES_HOSTS, help="OpenSearch hosts")
    parser.add_argument("--user", default=DEFAULT_ES_USER, help="OpenSearch user")
    parser.add_argument("--password", default=DEFAULT_ES_PASSWORD, help="OpenSearch password")
    parser.add_argument("--type", choices=["firewall", "http", "alerts", "all"], default="all", help="Event type to extract")
    parser.add_argument("--index", help="Index pattern override")
    parser.add_argument("--output", required=True, help="Output JSONL file")
    parser.add_argument("--sample-size", type=int, default=100000, help="Maximum events to extract")
    parser.add_argument("--start-time", help="Start time filter (e.g., '2026-01-01T00:00:00')")
    parser.add_argument("--end-time", help="End time filter")
    parser.add_argument("--stats", action="store_true", help="Show cluster statistics")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO)

    try:
        extractor = GraylogTrainingExtractor(
            hosts=args.hosts,
            user=args.user,
            password=args.password
        )

        # Stats mode
        if args.stats:
            stats = extractor.get_cluster_stats()
            print(json.dumps(stats, indent=2))
            return

        # Extract events
        all_events = []
        
        if args.type in ["firewall", "all"]:
            logger.info("Extracting firewall events...")
            firewall_events = extractor.extract_firewall_events(
                index_pattern=args.index if args.type == "firewall" else None,
                start_time=args.start_time,
                end_time=args.end_time,
                sample_size=args.sample_size
            )
            all_events.extend(firewall_events)

        if args.type in ["http", "all"]:
            logger.info("Extracting HTTP events...")
            http_events = extractor.extract_http_events(
                index_pattern=args.index if args.type == "http" else None,
                sample_size=args.sample_size
            )
            all_events.extend(http_events)

        if args.type in ["alerts", "all"]:
            logger.info("Extracting alert events...")
            alert_events = extractor.extract_alerts(
                index_pattern=args.index if args.type == "alerts" else None,
                sample_size=args.sample_size
            )
            all_events.extend(alert_events)

        # Write to JSONL
        with open(args.output, 'w') as f:
            for event in all_events:
                f.write(json.dumps(event) + '\n')

        logger.info(f"Extracted {len(all_events)} events total to {args.output}")

    except ImportError as e:
        print(f"ERROR: {e}")
        print("Install with: pip install opensearch-py")
        return 1
    except Exception as e:
        print(f"ERROR: {e}")
        import traceback
        traceback.print_exc()
        return 1

    return 0

if __name__ == "__main__":
    exit(main())