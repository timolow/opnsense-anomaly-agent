# OPNsense Anomaly Detection Agent

A self-learning ML-based network security monitoring system that ingests OPNsense firewall logs, detects attacks and anomalies in real time, and provides a SOC-style cyberpunk dashboard.

**57M+ events processed | 19 dashboard tabs | 25 test suites | Zero-downtime deploy**

## Architecture

```
OPNsense Firewall (UDP syslog :1514)
          │
          ▼
┌─────────────────────────────────────────────┐
│  anomaly-agent (Docker container)            │
│                                             │
│  syslog_listener  ──►  adaptive_parser       │
│       │                │                     │
│       ▼                ▼                     │
│  agent.py (main loop)                        │
│  ├── attack_detectors   (port scan, SYN flood, brute force, probes)
│  ├── anomaly_detector   (z-score volume spikes, temporal anomalies)
│  ├── baseline_engine    (per-rule traffic learning, hourly patterns)
│  ├── rule_classifier    (GradientBoosting ML, GOOD/SUSPICIOUS/ABUSIVE)
│  ├── threat_engine      (multi-source IP reputation scoring)
│  ├── geo_lookup         (MaxMind GeoLite2 + ip-api fallback)
│  ├── zenarmor_classifier (security gateway policy tracking)
│  ├── ids_analyzer       (Snort/Suricata signature analysis)
│  ├── nginx_monitor      (web attack detection)
│  ├── service_monitor    (DHCP, Unbound, NTP, OpenVPN, WireGuard)
│  ├── wan_flap_detector  (gateway up/down flapping)
│  ├── system_log_classifier (system log pattern learning)
│  ├── concept_drift      (ADWIN algorithm, stale baseline detection)
│  ├── threshold_tuner    (ROC-based auto-tuning, Phase 5)
│  ├── health_monitor     (subsystem checks, Discord status reporting)
│  ├── discord_bot        (rich embeds, slash commands, reconnection)
│  ├── apprise_notifier   (70+ platforms: Telegram, Slack, email, etc.)
│  └── server.py          (REST API :8766, SSE streaming, React SPA)
└──────┬──────────────────┬────────────────────┘
       │                  │
       ▼                  ▼
┌──────────────┐   ┌──────────────┐
│  PostgreSQL  │   │    Redis     │
│  (events,    │   │  (DNS cache, │
│   baselines) │   │   rate limit)│
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
- `anomaly-postgres` — PostgreSQL 16 (persistent event/anomaly storage)
- `anomaly-redis` — Redis 7 (DNS cache, rate limiting)
- `anomaly-agent` — The anomaly detection engine (syslog, ML, API, Discord, web UI)

Access the dashboard at `http://<server>:8766/`

## Web Dashboard

A React + TypeScript + Tailwind CSS SPA with a dark cyberpunk theme. All data is live from PostgreSQL.

| Tab | Description |
|-----|-------------|
| **Overview** | Stat cards, event timeline (uPlot), severity distribution, recent activity |
| **Heatmap** | IP-level traffic intensity grid |
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
| **Firewall Rules** | ML-classified rules (GOOD/SUSPICIOUS/ABUSIVE) with feedback |
| **Rules ML** | Model parameters, classification distribution, training status |
| **Syslogs** | Raw firewall log viewer with filtering |
| **Query Logs** | Advanced search by IP, time range |
| **Settings** | Detection thresholds, integration config, data management |

## ML Self-Learning Engine

The agent evolves its detection capabilities over 5 phases:

1. **Feedback Loop** — Users classify rules via thumbs up/down; incorrect labels downgrade confidence to UNCERTAIN
2. **Per-Rule Baselines** — Each rule learns volume, protocol distribution, port diversity, pass/block ratio, hourly patterns
3. **Temporal Patterns** — Z-score anomalies against 24-hour distribution with mean/stddev
4. **Active Learning Queue** — UNCERTAIN/low-confidence rules queued for human review
5. **Threshold Auto-Tuning** — ROC curve analysis adjusts detection thresholds to reduce false positives

**Implementation**: GradientBoosting classifier (18 features) with heuristic fallback. Concept drift detection via ADWIN algorithm. Baseline versioning with migration support.

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
| `GET /api/metrics` | Prometheus-format metrics for Grafana |
| `GET /api/sse` | Server-Sent Events stream for real-time dashboard updates |

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

- **172 tests** across all modules (adaptive_parser, reverse_dns, ml_learning, rule_classify, statistical_model, apprise_notifier, integration)
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