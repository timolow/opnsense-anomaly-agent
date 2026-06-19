#!/usr/bin/env python3
"""
Elasticsearch client for OPNsense anomaly detection agent.
Reads enriched firewall events from pfelk's Elasticsearch.

Usage:
    # Read recent firewall events
    python elasticsearch_client.py --index "pfelk-firewall-*" --size 100

    # Search for specific IP
    python elasticsearch_client.py --query '{"term": {"destination.ip": "192.168.1.1"}}'

    # Export to JSONL
    python elasticsearch_client.py --index "pfelk-firewall-*" --output events.jsonl
"""

import json
import logging
import argparse
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List

try:
    from elasticsearch import Elasticsearch, NotFoundError
    ES_AVAILABLE = True
except ImportError:
    ES_AVAILABLE = False

logger = logging.getLogger(__name__)

# ── Elasticsearch configuration ──
DEFAULT_ES_HOST = "http://192.168.99.12:9200"
DEFAULT_ES_USER = "elastic"
DEFAULT_ES_INDEX = "pfelk-firewall-*"


class ElasticsearchClient:
    """Client for reading enriched events from pfelk's Elasticsearch."""

    def __init__(self, host: str = DEFAULT_ES_HOST, user: str = DEFAULT_ES_USER,
                 password: str = "changeme", index: str = DEFAULT_ES_INDEX):
        if not ES_AVAILABLE:
            raise ImportError("elasticsearch package not installed. Run: pip install elasticsearch")

        self.es = Elasticsearch(
            [host],
            basic_auth=(user, password),
            verify_certs=False,  # Self-signed or local
            retry_on_timeout=True,
            max_retries=3,
        )
        self.index = index
        self._connected = False

    def connect(self) -> bool:
        """Test connection to Elasticsearch."""
        try:
            info = self.es.info()
            version = info.get("version", {}).get("number", "unknown")
            logger.info(f"Connected to Elasticsearch {version} at {self.es.transport.hosts}")
            self._connected = True
            return True
        except Exception as e:
            logger.error(f"Failed to connect to Elasticsearch: {e}")
            self._connected = False
            return False

    def is_connected(self) -> bool:
        return self._connected

    def get_indices(self) -> List[str]:
        """List all pfelk indices."""
        try:
            indices = self.es.indices.get_index(index=self.index)
            return sorted(indices)
        except Exception as e:
            logger.error(f"Failed to list indices: {e}")
            return []

    def get_event_count(self) -> int:
        """Get total event count for index pattern."""
        try:
            result = self.es.count(index=self.index)
            return result["count"]
        except Exception as e:
            logger.error(f"Failed to get event count: {e}")
            return 0

    def search_events(self, query: Optional[Dict] = None, size: int = 100,
                      sort: str = "@timestamp", order: str = "desc") -> List[Dict[str, Any]]:
        """
        Search for firewall events.

        Args:
            query: Elasticsearch query dict (default: match_all)
            size: Number of results to return
            sort: Field to sort by
            order: Sort order (asc/desc)

        Returns:
            List of event documents
        """
        if not self.connect():
            return []

        if query is None:
            query = {"match_all": {}}

        try:
            result = self.es.search(
                index=self.index,
                query=query,
                size=size,
                sort=[{sort: {"order": order}}],
                _source=True,
            )

            events = []
            for hit in result["hits"]["hits"]:
                event = hit["_source"]
                # Add document ID for reference
                event["_id"] = hit["_id"]
                event["_index"] = hit["_index"]
                events.append(event)

            return events

        except Exception as e:
            logger.error(f"Search failed: {e}")
            return []

    def get_recent_events(self, hours: int = 1, size: int = 100) -> List[Dict[str, Any]]:
        """Get recent events within the last N hours."""
        query = {
            "bool": {
                "must": [
                    {
                        "range": {
                            "@timestamp": {
                                "gte": f"now-{hours}h",
                                "lte": "now"
                            }
                        }
                    }
                ]
            }
        }
        return self.search_events(query=query, size=size, sort="@timestamp", order="desc")

    def get_events_by_ip(self, ip: str, size: int = 100) -> List[Dict[str, Any]]:
        """Get events for a specific IP (source or destination)."""
        query = {
            "bool": {
                "should": [
                    {"term": {"source.ip": ip}},
                    {"term": {"destination.ip": ip}}
                ],
                "minimum_should_match": 1
            }
        }
        return self.search_events(query=query, size=size)

    def get_events_by_action(self, action: str, size: int = 100) -> List[Dict[str, Any]]:
        """Get events with a specific action (PASS, BLOCK, etc.)."""
        query = {
            "term": {"event.action": action.upper()}
        }
        return self.search_events(query=query, size=size)

    def get_events_by_interface(self, interface: str, size: int = 100) -> List[Dict[str, Any]]:
        """Get events for a specific interface."""
        query = {
            "term": {"interface.name": interface}
        }
        return self.search_events(query=query, size=size)

    def get_events_by_rule(self, rule_id: str, size: int = 100) -> List[Dict[str, Any]]:
        """Get events matched by a specific rule."""
        query = {
            "term": {"rule.id": rule_id}
        }
        return self.search_events(query=query, size=size)

    def export_to_jsonl(self, output_file: str, query: Optional[Dict] = None,
                        size: int = 10000) -> int:
        """Export events to JSONL file."""
        if not self.connect():
            return 0

        events = self.search_events(query=query, size=size)
        count = 0

        with open(output_file, 'w') as f:
            for event in events:
                # Remove internal fields
                clean_event = {k: v for k, v in event.items() if not k.startswith('_')}
                f.write(json.dumps(clean_event) + '\n')
                count += 1

        logger.info(f"Exported {count} events to {output_file}")
        return count

    def get_stats(self) -> Dict[str, Any]:
        """Get index statistics."""
        if not self.connect():
            return {}

        try:
            stats = self.es.indices.stats(index=self.index)
            idx_stats = stats["indices"]
            total_docs = 0
            total_store = 0

            for idx_name, idx_info in idx_stats.items():
                total_docs += idx_info.get("total", {}).get("docs", {}).get("count", 0)
                total_store += idx_info.get("store", {}).get("size_in_bytes", 0)

            return {
                "indices": list(idx_stats.keys()),
                "total_documents": total_docs,
                "total_store_bytes": total_store,
                "total_store_mb": round(total_store / (1024 * 1024), 2),
            }
        except Exception as e:
            logger.error(f"Failed to get stats: {e}")
            return {}


def main():
    parser = argparse.ArgumentParser(description="Elasticsearch client for pfelk events")
    parser.add_argument("--host", default=DEFAULT_ES_HOST, help="Elasticsearch host")
    parser.add_argument("--user", default=DEFAULT_ES_USER, help="Elasticsearch user")
    parser.add_argument("--password", default="changeme", help="Elasticsearch password")
    parser.add_argument("--index", default=DEFAULT_ES_INDEX, help="Index pattern")
    parser.add_argument("--query", type=str, help="JSON query string")
    parser.add_argument("--size", type=int, default=100, help="Number of results")
    parser.add_argument("--output", type=str, help="Output JSONL file")
    parser.add_argument("--hours", type=int, default=1, help="Hours back for recent events")
    parser.add_argument("--ip", type=str, help="Filter by IP address")
    parser.add_argument("--action", type=str, help="Filter by action (PASS/BLOCK)")
    parser.add_argument("--interface", type=str, help="Filter by interface")
    parser.add_argument("--stats", action="store_true", help="Show index stats")
    parser.add_argument("--list-indices", action="store_true", help="List indices")
    parser.add_argument("--count", action="store_true", help="Show event count")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO)

    try:
        client = ElasticsearchClient(
            host=args.host,
            user=args.user,
            password=args.password,
            index=args.index,
        )

        # Stats mode
        if args.stats:
            stats = client.get_stats()
            print(json.dumps(stats, indent=2))
            return

        # List indices
        if args.list_indices:
            indices = client.get_indices()
            for idx in indices:
                print(idx)
            return

        # Count
        if args.count:
            count = client.get_event_count()
            print(f"Total events: {count}")
            return

        # Build query from filters
        query = None
        if args.query:
            query = json.loads(args.query)
        elif args.ip:
            query = {
                "bool": {
                    "should": [
                        {"term": {"source.ip": args.ip}},
                        {"term": {"destination.ip": args.ip}}
                    ],
                    "minimum_should_match": 1
                }
            }
        elif args.action:
            query = {"term": {"event.action": args.action.upper()}}
        elif args.interface:
            query = {"term": {"interface.name": args.interface}}

        # Get events
        if query:
            events = client.search_events(query=query, size=args.size)
        elif args.hours:
            events = client.get_recent_events(hours=args.hours, size=args.size)
        else:
            events = client.get_recent_events(hours=1, size=args.size)

        # Output
        if args.output:
            count = client.export_to_jsonl(args.output, query, args.size)
            print(f"Exported {count} events to {args.output}")
        else:
            for event in events[:20]:  # Limit output
                print(json.dumps(event, indent=2, default=str))
            if len(events) > 20:
                print(f"... and {len(events) - 20} more events")

    except ImportError as e:
        print(f"ERROR: {e}")
        print("Install with: pip install elasticsearch")
        return 1
    except Exception as e:
        print(f"ERROR: {e}")
        import traceback
        traceback.print_exc()
        return 1

    return 0


if __name__ == "__main__":
    exit(main())
