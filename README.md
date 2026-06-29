# OPNsense Anomaly Detection Agent

A self-learning ML-based network security monitoring system that ingests OPNsense firewall logs, detects attacks and anomalies in real time, and provides a SOC-style cyberpunk dashboard.

**57M+ events processed | 19 dashboard tabs | 25 test suites | Zero-downtime deploy**

## Architecture

```
OPNsense Firewall (UDP syslog :1514)
          │
          ▼
┌───────────────────────────────────────────────────┐
│  anomaly-agent (Docker container)                  │
│                                                    │
│  syslog_listener ──► adaptive_parser               │
│       │                │                           │
│       ▼                ▼                           │
│  agent.py (main loop)                              │
│  ├── attack_detectors  (port scan, SYN flood, brute force, probes)
│  ├── anomaly_detector  (z-score volume spikes, temporal anomalies)
│  ├── baseline_engine   (per-rule traffic learning, hourly patterns)
│  ├── threat_engine     (multi-source IP reputation scoring)
│  ├── geo_lookup        (MaxMind GeoLite2 + ip-api fallback)
│  ├── zenarmor_classifier (security gateway policy tracking)
│  ├── ids_analyzer      (Snort/Suricata signature analysis)
│  ├── nginx_monitor     (web attack detection)
│  ├── service_monitor   (DHCP, Unbound, NTP, OpenVPN, WireGuard)
│  ├── wan_flap_detector (gateway up/down flapping)
│  ├── system_log_classifier (system log pattern learning)
│  ├── concept_drift     (ADWIN algorithm, stale baseline detection)
│  ├── health_monitor    (subsystem checks, Discord status reporting)
│  ├── discord_bot       (rich embeds, slash commands, reconnection)
│  ├── apprise_notifier  (70+ platforms: Telegram, Slack, email, etc.)
│  └── server.py         (REST API :8766, SSE streaming, React SPA)
│
│  ─── Behavioral ML Pipeline (ML-PIVOT) ────       │
│  ├── signal_bus        (unified signal routing, 51 signal types)
│  ├── correlation_engine (attack chain detection, incident grouping)
│  ├── incident_manager  (lifecycle state machine, feedback loop)
│  ├── ip_behavior_model (per-IP behavioral profiles, EMA baselines)
│  └── flow_classifier   (GradientBoosting flow classification)
└──────┬──────────────────┬──────────────────────────┘
       │                  │
       ▼                  ▼
┌──────────────┐   ┌──────────────┐
│  PostgreSQL  │   │    Redis     │
│  (events,    │   │  (DNS cache, │
│   baselines, │   │   rate limit)│
│   incidents) │   │              │
└──────────────┘   └──────────────┘
```

## Quick Start

### 1. Clone and Configure

```bash
git clone https://github.com/timolow/opnsense-anomaly-agent.git
cd opnsense-anomaly-agent
cp .env.example .env
# Edit .env with your OPNsense API credentials and Discord token
```

### 2. Configure OPNsense to Send Syslog

1. **System > Settings > Log Settings > Log Targets** — Add remote log host
2. **Host**: Your server's IP, **Protocol**: UDP, **Port**: 1514
3. **Log Level**: At minimum `Filterlog`
4. Save and apply

### 3. Deploy

```bash
docker compose up -d
```

This starts three containers:
- `anomaly-postgres` — PostgreSQL 16 (persistent event/anomaly/incident storage)
- `anomaly-redis` — Redis 7 (DNS cache, rate limiting)
- `anomaly-agent` — The anomaly detection engine (syslog, ML, API, Discord, web UI)

Access the dashboard at `http://<server>:8766/`

## Web Dashboard

A React + TypeScript + Tailwind CSS SPA with a dark cyberpunk theme. All data is live from PostgreSQL.

| Tab | Description |
|-----|-------------|
| **Overview** | Stat cards, event timeline (uPlot), severity distribution, recent activity |
| **Heatmap** | IP-level traffic intensity grid with behavioral threat coloring |
| **Behavioral** | ML behavioral overview: IP profiles, incident stats, threat scores |
| **IP Profiles** | Per-IP behavioral profiles with threat scores, event breakdowns |
| **Flow ML** | GradientBoosting flow classification (GOOD/SUSPICIOUS/ABUSIVE) |
| **Incidents** | Correlated attack chains with timeline visualization |
| **Baselines** | Signal bus monitoring, concept drift, severity distribution |
| **Flow Map** | Sankey diagram of source→destination flows |
| **IP Flow** | Detailed per-IP event counts and direction |
| **Geography** | Country/region breakdown with intensity map |
| **Alerts** | Anomaly alerts with severity filtering |
| **Mutes** | Manage muted IPs (skip alerting for known false positives) |
| **ZenArmor** | Security gateway policy tracking and anomaly detection |
| **IDS** | Snort/Suricata signature analysis and frequency tracking |
| **OPNsense Status** | Live system stats: memory, CPU, services, interfaces, gateways |
| **Services** | DHCP, Unbound, NTP, OpenVPN, WireGuard health |
| **Nginx Monitor** | Web traffic analysis and attack detection |
| **Network Topology** | Force graph of IP connections (30+ nodes) |
| **WAN Flap Detection** | Gateway stability timeline |
| **Firewall Rules** | Rule tracking and management |
| **Syslogs** | Raw firewall log viewer with filtering |
| **Query Logs** | Advanced search by IP, time range |
| **Settings** | Detection thresholds, integration config, data management |

## ML-PIVOT Behavioral Engine

The behavioral ML pipeline processes every event through a unified signal bus, correlates related signals into incidents, and maintains per-IP behavioral profiles with exponential moving average baselines.

### Signal Bus
Unified signal routing with 51 signal types. Every detector output (attack, anomaly, geo, behavior, flow) flows through the bus before persistence. Thread-safe bounded queue with subscriber pattern.

### Correlation Engine
Groups related signals into incidents using IP proximity and temporal windows. Detects multi-stage attack chains (e.g. scan → exploit → exfiltration). Severity escalation based on signal density and attack phase coverage.

### Incident Manager
Full lifecycle state machine (OPEN → ACTIVE → ESCALATED → MITIGATED → RESOLVED). Feedback loop for false positive correction. Auto-resolution of stale incidents. Discord integration for real-time incident reporting.

### IP Behavior Model
Per-IP behavioral profiles with exponential moving average baselines. Tracks event volume, protocol distribution, port diversity, pass/block ratio, and hourly patterns. Anomaly detection via z-score deviation from learned baselines.

### Flow Classifier
GradientBoosting classifier for network flow categorization. Trained on protocol, port, volume, duration, and direction features. Classifies flows as GOOD, SUSPICIOUS, or ABUSIVE with confidence scoring.

## Notifications

### Discord (built-in)
Rich embed alerts with severity coloring, attack details, IP info. Slash commands:
- `/status` — Agent health, event counts, uptime
- `/alerts` — Recent anomaly alerts
- `/mute <ip>` — Mute an IP for 1 hour
- `/search <query>` — Search by IP or rule
- `/top-threats` — Top blocked/threat IPs
- `/recent-alerts` — Last 10 alerts
- `/help` — Command list

Reconnection with exponential backoff on disconnect. Per-user rate limiting on commands.

### Apprise (optional — 70+ platforms)

```env
APPRISE_URLS=tgram://BOT_TOKEN/CHAT_ID,slack://WEBHOOK_URL,mailto://user:pass@host?to=recipient@example.com
```

Graceful degradation: if Apprise is unavailable, alerts continue to Discord only.

## REST API

All endpoints served on port 8766. HTTP Basic Auth via `DASHBOARD_API_USER`/`DASHBOARD_API_PASS` (optional).

| Endpoint | Description |
|----------|-------------|
| `GET /api/health` | Subsystem health (PostgreSQL, Redis, OPNsense, syslog, Discord, disk) |
| `GET /api/stats` | Event counters, severity breakdown, unique IPs, anomalies |
| `GET /api/timeline` | Traffic volume over time (hourly/daily buckets) |
| `GET /api/alerts` | Recent anomaly alerts |
| `GET /api/events` | Recent firewall events |
| `GET /api/heatmap` | IP traffic heatmap data |
| `GET /api/ip-flow` | Source→destination flow data |
| `GET /api/geo` | Geographic IP classification |
| `GET /api/rules` | ML-classified firewall rules |
| `POST /api/feedback` | Submit rule classification feedback |
| `GET /api/opnsense` | OPNsense system status (memory, interfaces, gateways, services) |
| `GET /api/zenarmor-summary` | ZenArmor policy overview |
| `GET /api/ids-summary` | IDS signature overview |
| `GET /api/services` | Service monitor status |
| `GET /api/mutes` | Muted IP list |
| `POST /api/mutes/<ip>` | Mute/unmute an IP |
| `GET /api/ml` | ML engine status (accuracy, rules trained, self-learning) |
| `GET /api/ml-model` | Model info and training status |
| `GET /api/ml-classifications` | Per-rule classification details |
| `GET /api/drift` | Concept drift detection status |
| `GET /api/metrics` | Agent metrics (JSON format) |
| `GET /api/sse` | Server-Sent Events stream for real-time dashboard updates |

### ML-PIVOT Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /api/behavior-profiles` | Per-IP behavioral profiles with threat scores |
| `GET /api/behavior-overview` | Combined behavioral overview (profiles + incidents + signals) |
| `GET /api/flow-classifications` | ML flow classification results |
| `GET /api/flow-classifications-by-ip` | Flow classifications filtered by IP |
| `GET /api/signal-bus/stats` | Signal bus statistics and recent signals |
| `GET /api/incidents` | Correlated incidents with timeline data |
| `GET /api/incidents/stats` | Incident statistics by severity and phase |
| `POST /api/incidents/inc_<id>/transition` | Incident state transition |

## Zero-Downtime Deployment

Blue-green deployment with health-check gating:

```bash
./deploy.sh              # Deploy current HEAD
./deploy.sh --tag v1.2.3 # Deploy with custom tag
./rollback.sh            # Rollback to previous version
```

Process: build → staging container on port 8767 → health check → swap → verify → prune old images. Aborts on any failure, leaving old version running.

## Configuration

Key environment variables (full list in `.env.example`):

| Variable | Default | Description |
|----------|---------|-------------|
| `OPN_HOST` | `192.168.1.1` | OPNsense IP |
| `OPN_PORT` | `6666` | OPNsense API port |
| `OPN_API_KEY` | *(required)* | OPNsense API key |
| `OPN_API_SECRET` | *(required)* | OPNsense API secret |
| `DISCORD_TOKEN` | *(required)* | Discord bot token |
| `DISCORD_CHANNEL_ID` | *(required)* | Alert channel ID |
| `OWN_WAN_IPS` | *(required)* | Your WAN IPs (comma-separated) |
| `SYSLOG_ENABLED` | `true` | Built-in UDP syslog listener |
| `SYSLOG_UDP_PORT` | `1514` | Syslog receive port |
| `REVERSE_DNS_ENABLED` | `false` | PTR lookups with Redis cache |
| `BATCH_SIZE` | `100` | Event batch processing size |
| `PORTSCAN_THRESHOLD` | `10` | Unique destinations to flag scan |
| `STAT_ZSCORE` | `3.0` | Z-score anomaly threshold |

## CI/CD

- **172 tests** across all modules (adaptive_parser, reverse_dns, ml_learning, rule_classify, statistical_model, apprise_notifier, integration, ml_pipeline)
- **17 ML-PIVOT integration tests** (SignalBus, CorrelationEngine, IPBehaviorModel, FlowClassifier, FullPipeline)
- **Docker build** — Multi-platform images pushed to GHCR on every push to `master`
- **CodeQL** — Automated security scanning on every commit
- **Tagged releases** — Images tagged with commit SHA and `latest`

## Requirements

- Docker and Docker Compose (recommended)
- Python 3.11+ (for standalone syslog listener)
- Discord bot token
- OPNsense firewall with syslog forwarding enabled

## License

MIT
