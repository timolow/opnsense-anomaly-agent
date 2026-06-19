# pfelk Integration for OPNsense Anomaly Detection

## Overview

This directory contains the configuration for integrating [pfelk](https://github.com/pfelk/pfelk)
into the OPNsense anomaly detection stack. pfelk provides:

- **Syslog ingestion** from OPNsense on port 5140 (UDP/TCP)
- **Grok-based parsing** of filterlog into structured fields
- **Elasticsearch storage** with rich schema
- **Kibana dashboards** for visualization

## Architecture

```
OPNsense Firewall (192.168.1.1)
    │
    ├──► Syslog UDP:5140 ──► pfelk Logstash (192.168.99.12:5140)
    │                            │
    │                            ├──► Grok parse (filterlog CSV → structured fields)
    │                            │
    │                            └──► Elasticsearch (192.168.99.12:9200)
    │                                   │
    │                                   ├──► pfelk-firewall-* indices
    │                                   │
    │                                   └──► Kibana (192.168.99.12:5601)
    │                                           │
    │                                           └──► Dashboards & visualization
    │
    └──► Syslog UDP:1514 ──► Anomaly Agent (192.168.1.50:1514)
                                │
                                ├──► AdaptiveParser (Python)
                                │
                                └──► PostgreSQL (events, anomalies)
```

Both systems can run in parallel:
- **pfelk**: Rich parsing, Kibana dashboards, Elasticsearch storage
- **Anomaly Agent**: Python-based detection, PostgreSQL storage, Discord alerts

## Quick Start

### 1. Deploy pfelk on vLLM Server

```bash
# On your local machine
cd /Users/timolow/opnsense-anomaly-agent/pfelk
chmod +x deploy-pfelk.sh

# Deploy to vLLM server (192.168.99.12)
./deploy-pfelk.sh tim@192.168.99.12
```

### 2. Configure OPNsense Remote Logging

In OPNsense web UI:
1. **System > Settings > Logging > Log targets**
2. Add new log target:
   - **Destination**: `192.168.99.12`
   - **Port**: `5140`
   - **Protocol**: `UDP` (or TCP for reliability)
   - **Log facilities**: `kern` (filterlog)
   - **Format**: `Filterlog (CSV format)`

### 3. Verify Deployment

```bash
# Check pfelk status
ssh tim@192.168.99.12 "cd ~/pfelk && docker compose ps"

# Test Elasticsearch
curl -s -u elastic:changeme http://192.168.99.12:9200/

# Test Kibana
open http://192.168.99.12:5601
```

### 4. Query Events from Anomaly Agent

```bash
# Install Elasticsearch client
pip install elasticsearch

# Get recent events
python elasticsearch_client.py --hours 1 --size 50

# Search by IP
python elasticsearch_client.py --ip 192.168.1.1 --size 100

# Search by action
python elasticsearch_client.py --action PASS --size 100

# Export to JSONL
python elasticsearch_client.py --index "pfelk-firewall-*" --output events.jsonl --size 1000

# Show stats
python elasticsearch_client.py --stats

# List indices
python elasticsearch_client.py --list-indices

# Count events
python elasticsearch_client.py --count
```

## File Structure

```
pfelk/
├── docker-compose.yml          # Single-node ELK stack
├── .env                        # Environment configuration
├── deploy-pfelk.sh             # Deployment script
└── pfelk-config/
    ├── logstash/
    │   ├── pipeline/
    │   │   └── pfelk.conf      # Logstash pipeline (syslog → ES)
    │   └── patterns/
    │       └── pfelk.grok      # Grok patterns for OPNsense
```

## Configuration

### docker-compose.yml

- **Elasticsearch**: Single node, 2GB RAM, port 9200
- **Kibana**: Port 5601, connects to ES
- **Logstash**: Port 5140 (UDP/TCP), parses syslog

### .env

- `STACK_VERSION`: Elastic stack version (default: 8.17.0)
- `ELASTIC_PASSWORD`: Elasticsearch password
- `KIBANA_PASSWORD`: Kibana system user password
- `ES_MEM_LIMIT`: Elasticsearch memory limit (default: 2g)

### pfelk.conf (Logstash pipeline)

The pipeline:
1. **Ingest**: UDP/TCP syslog on port 5140
2. **Grok**: Parse OPNsense syslog header with OPNSENSE pattern
3. **CSV Split**: Parse filterlog CSV into structured fields
4. **Date**: Parse timestamp
5. **Output**: Index to Elasticsearch

### pfelk.grok (Patterns)

Defines patterns for:
- `OPNSENSE`: Syslog header parsing
- `PFSENSE`: Legacy pfSense format
- `RFC5424`: RFC 5424 format
- `CAPTIVEPORTAL`: Captive portal logs
- `DHCPD`: DHCP server logs
- `SURICATA`: IDS logs

## Data Schema

pfelk parses filterlog CSV into these fields:

```json
{
  "rule.id": "230",
  "rule.uuid": "fae559338f65e11c53669fc3642c93c2",
  "interface.name": "ixl2",
  "event.reason": "match",
  "event.action": "pass",
  "network.direction": "out",
  "network.type": "4",
  "network.protocol": "tcp",
  "source.ip": "192.168.1.1",
  "destination.ip": "192.168.1.8",
  "source.port": 35220,
  "destination.port": 1234,
  "pf.packet.length": 60,
  "pf.tcp.flags": "S",
  "@timestamp": "2026-06-13T17:16:45.189886Z"
}
```

## Integration with Anomaly Agent

The anomaly agent can consume pfelk data in two ways:

### Option A: Read from Elasticsearch (recommended)

```python
from elasticsearch_client import ElasticsearchClient

es = ElasticsearchClient(
    host="http://192.168.99.12:9200",
    user="elastic",
    password="changeme",
)
es.connect()

# Get recent blocked events
blocked = es.get_events_by_action("BLOCK", size=1000)

# Get events for suspicious IP
suspicious = es.get_events_by_ip("10.0.0.99", size=100)
```

### Option B: Keep parallel ingestion

- OPNsense sends syslog to BOTH 192.168.1.50:1514 (agent) and 192.168.99.12:5140 (pfelk)
- Agent continues using PostgreSQL
- pfelk provides Kibana dashboards and Elasticsearch for rich queries

## Monitoring

### Health Checks

```bash
# Elasticsearch health
curl -s http://192.168.99.12:9200/_cluster/health

# Index stats
curl -s http://192.168.99.12:9200/pfelk-firewall-*/_stats

# Logstash pipeline stats
curl -s http://192.168.99.12:9600/_node/pipelines
```

### Log Review

```bash
# Elasticsearch logs
ssh tim@192.168.99.12 "docker logs elasticsearch --tail 50"

# Kibana logs
ssh tim@192.168.99.12 "docker logs kibana --tail 50"

# Logstash logs
ssh tim@192.168.99.12 "docker logs logstash --tail 50"
```

## Troubleshooting

### pfelk not receiving syslog

1. Verify OPNsense remote logging configuration
2. Check firewall rules allow UDP 5140 from OPNsense to vLLM server
3. Verify Logstash is listening: `netstat -an | grep 5140`
4. Check Logstash logs: `docker logs logstash --tail 100`

### Elasticsearch not starting

1. Verify `vm.max_map_count >= 262144`: `sysctl vm.max_map_count`
2. Check memory: Elasticsearch needs at least 1GB allocated
3. Review logs: `docker logs elasticsearch`

### Kibana not accessible

1. Verify Kibana is running: `docker compose ps`
2. Check Kibana logs: `docker logs kibana --tail 100`
3. Ensure ES is healthy: `curl http://localhost:9200/_cluster/health`

## Resources

- [pfelk GitHub](https://github.com/pfelk/pfelk)
- [pfelk Wiki](https://github.com/pfelk/pfelk/wiki)
- [Elasticsearch Docs](https://www.elastic.co/guide/en/elasticsearch/reference/current/index.html)
- [Kibana Docs](https://www.elastic.co/guide/en/kibana/current/index.html)
- [Logstash Docs](https://www.elastic.co/guide/en/logstash/current/index.html)
