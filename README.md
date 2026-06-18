# OPNsense Anomaly Detection Agent

A lightweight anomaly detection agent that monitors OPNsense firewall logs, learns normal traffic patterns, detects attacks and service anomalies, and sends alerts via Discord, Apprise (70+ platforms), or both.

## Architecture

```
OPNsense Firewall
       |
       | (UDP syslog on port 1514)
       v
┌─────────────────────────┐
│ syslog_listener         │ ← Standalone script OR built-in to Docker
│                         │    Parses filterlog CSV, writes JSONL
└────────┬────────────────┘
         |
         | (syslog_events.jsonl)
         v
┌─────────────────────────┐
│ anomaly agent (Docker)  │    Detects anomalies, sends alerts,
│                         │    serves web dashboard + REST API (8766)
│                         │    ML self-learning engine (5 phases)
│                         │    Reverse DNS resolver + hostname map
│                         │    Rule classifier (GOOD/SUSPICIOUS/ABUSIVE)
│                         │    Apprise notifications (70+ platforms)
└────────┬────────────────┘
         |
         | (Discord API + Apprise)
         v
┌─────────────────────────┐
│    Discord + Apprise    │    Alerts via multiple channels
└─────────────────────────┘
```

### Syslog Listener — Two Modes

| Mode | How | When |
|---|---|---|
| **Standalone** | Run `python3 syslog_listener.py` on any machine | When you want to decouple log collection from detection |
| **Built-in** | Included in the Docker container (no separate process) | When you want a single container for everything |

When using **standalone mode**, the JSONL file must be shared with the Docker agent via volume mount or shared directory.

### Detection Capabilities

- **New source IPs** — External addresses seen for the first time
- **Unusual ports** — Traffic to ports not seen in recent history
- **High event rates** — Unusually high volume of firewall events from a single source
- **Port scans** — Single source connecting to many different destinations
- **Data exfiltration indicators** — Outbound connections to unusual destinations
- **Brute force detection** — Repeated auth-related actions from the same source
- **New service detection** — New services appearing on the network
- **Protocol anomalies** — Unusual protocol usage patterns
- **WAN flap detection** — Gateway up/down flapping alerts
- **Service anomalies** — DHCP, Unbound, NTP, OpenVPN, WireGuard issues
- **System log anomalies** — Unusual patterns in OPNsense system logs (interfaces, routing, DHCP)
- **ZenArmor policy tracking** — Security gateway policy classification (ALLOW/BLOCK/MIXED), new policy detection, policy change detection, block rate anomaly alerts
- **ZenArmor anomalies** — NEW_POLICY, POLICY_CHANGE, BLOCK_SPIKE, MIXED_POLICY, SYSTEM_BLOCK_SPIKE detection
- **IDS signature tracking** — Snort/Suricata signature classification by priority (HIGH/MEDIUM/LOW), signature frequency analysis, new signature detection
- **IDS anomalies** — NEW_SIGNATURE, SIGNATURE_SPIKE, TARGET_CHANGE, CROSS_NETWORK, MULTIPLE_NEW_SIGNATURES detection

## Quick Start

### 1. Clone and Configure

```bash
git clone https://github.com/timolow/opnsense-anomaly-agent.git
cd opnsense-anomaly-agent
```

### 2. Configure Secrets

Edit `.env` with your credentials (copy from `.env.example`):

```bash
# OPNsense firewall
OPN_HOST=192.168.1.1
OPN_PORT=6666
OPN_API_KEY=your_api_key_here
OPN_API_SECRET=your_api_secret_here
OPN_VERIFY_SSL=false

# Discord bot
DISCORD_TOKEN=your_discord_bot_token_here
DISCORD_CHANNEL_ID=your_channel_id_here

# Network classification
OWN_WAN_IPS=YOUR_WAN_IP_HERE
WAN_IP_MIN_EVENTS=10
MAX_WAN_IPS=10000

# Agent configuration
CHAT_PORT=8765
SYSLOG_ENABLED=true
SYSLOG_UDP_PORT=1514

# Reverse DNS
REVERSE_DNS_ENABLED=true
REVERSE_DNS_SERVER=192.168.1.1
```

### 3. Configure OPNsense to Send Syslog

On your OPNsense firewall, configure syslog output:

1. **System > Settings > Log Settings > Log Targets** — Add a new target
2. **Remote Log Host**: Your machine's IP address
3. **Protocol**: UDP
4. **Port**: 1514 (or the port you set in `SYSLOG_UDP_PORT`)
5. **Log Level**: Select at minimum `Filterlog`
6. Save and apply

---

### Deployment: Docker Compose (Recommended)

Everything runs in three containers: PostgreSQL, Redis, and the anomaly agent.

```bash
# Start everything
docker compose up -d
```

This starts:
- `anomaly-postgres` — PostgreSQL 16 for persistent event storage
- `anomaly-redis` — Redis 7 for reverse DNS caching
- `anomaly-agent` — The anomaly detection agent (includes syslog listener, ML engine, web dashboard, REST API, Discord bot, Apprise notifications)

No separate syslog listener process needed.

**Volume mounts:**
- `./app.html:/app/app.html:ro` — Web UI (hot-swappable, no rebuild needed)
- `./agent_data:/app/agent_data` — Persistent learned patterns, events, mutes
- `./data:/app/data` — GeoLite2 database

#### Using Pre-built Docker Images

The project publishes Docker images to GitHub Container Registry (GHCR). To use a pre-built image instead of building locally:

```bash
# Set in .env
AGENT_IMAGE=ghcr.io/timolow/opnsense-anomaly-agent:latest
```

Then restart:
```bash
docker compose up -d
```

---

### Chat Commands

The agent runs an HTTP server on port 8765 for chat commands. Send commands from any Discord channel:

| Command | Description |
|---|---|
| `!status` | Show current agent status (events processed, anomalies detected, uptime) |
| `!topblocked` | Show top blocked source IPs |
| `!help` | Show all available commands |

## Web Dashboard

A comprehensive responsive web UI is served at `http://<server>:8766/` with a collapsible sidebar organized into categories:

- **Dashboard** (`overview`) — Overall stats, incident timeline, traffic heatmaps
- **Alerts** (`alerts`) — Recent anomaly alerts with severity and filtering
- **Flows** (`flows`) — IP flow visualization and bandwidth tracking
- **Threats** (`heatmap`, `ipflow`, `geo`) — Traffic heatmaps, detailed IP flows, geographic analysis
- **Network** (`network`, `mutes`) — Network classification, muted IP management
- **Rules** (`rules`) — ML-classified firewall rules (GOOD/SUSPICIOUS/ABUSIVE)
- **Services** (`services`) — DHCP, Unbound, NTP, OpenVPN, WireGuard status
- **Logs** (`syslogs`, `logs`) — System log viewer with filtering
- **OPNsense** (`opnsense`) — OPNsense API proxy for gateway status, interfaces, routing
- **Settings** (`settings`) — Agent configuration, stats, and health

All tabs are searchable, filterable, and support dark/light theme auto-detection.

## Notifications

The agent supports two notification systems:

### Discord (built-in)
Rich embed alerts to a Discord channel with attack details, severity, and IP info.

### Apprise (multi-platform — optional)
Apprise provides unified alerting to **Telegram, Slack, Email, SMS, PushBullet, Gotify, Matrix, and 70+ other platforms** via a simple URI scheme. No additional hosted infrastructure required.

[Apprise Documentation](https://github.com/caronc/apprise)

**Setup:**
1. Install: `pip install apprise>=1.9.0`
2. Add `APPRISE_URLS` to `.env` with comma-separated URIs:
   ```env
   APPRISE_URLS=tgram://BOT_TOKEN/CHAT_ID,slack://webhook_url,mailto://user:pass@emailhost?to=recipient@example.com
   ```
3. Restart the agent

**Supported Apprise URLs:**
| Platform | Example URI |
|----------|------------|
| Telegram | `tgram://BOT_TOKEN/CHAT_ID` |
| Slack | `slack://webhook_url` |
| Email | `mailto://user:pass@emailhost?to=recipient@example.com` |
| PushBullet | `pbul://API_TOKEN` |
| Gotify | `gotify://gotify.host/token` |
| Matrix | `matrix://homeserver/token/room_id` |
| Webhook | `json://hostname/path` |

**Notes:**
- Apprise is **optional** — the agent runs fine without it
- Graceful degradation: if Apprise isn't installed or URLs are invalid, alerts continue to Discord
- All alerts (attack, geo, service, WAN flap, system log) are sent through both channels

## REST API

The dashboard API is served on port 8766. Key endpoints include:

| Endpoint | Description |
|---|---|
| `GET /api/health` | Health check |
| `GET /api/stats` | Current agent statistics |
| `GET /api/rules` | All firewall rules |
| `GET /api/rules/<uuid>` | Individual rule detail |
| `GET /api/alerts` | Recent anomaly alerts |
| `GET /api/events` | Recent events |
| `GET /api/flows` | IP flow data |
| `GET /api/geo` | Geographic IP data |
| `GET /api/heatmap` | Traffic heatmap data 
| `GET /api/opnsense` | OPNsense connection status |
| `GET /api/service-status` | Service monitor status |
| `GET /api/heartbeat` | Agent heartbeat |
| `GET /api/zenarmor-summary` | ZenArmor policy summary |
| `GET /api/zenarmor-policies` | All known ZenArmor policies |
| `GET /api/zenarmor-events` | Recent ZenArmor events (with limit/offset) |
| `GET /api/zenarmor-anomalies` | Recent ZenArmor anomalies |
| `GET /api/ids-summary` | IDS signature summary |
| `GET /api/ids-signatures` | All known IDS signatures |
| `GET /api/ids-events` | Recent IDS events (with limit/offset) |
| `GET /api/ids-anomalies` | Recent IDS anomalies |
| `GET /api/ip/<ip>` | Detailed IP flow analysis |
| `GET /api/system_logs` | System log entries |
| `GET /api/services` | Service status (DHCP, Unbound, NTP, etc.) |
| `GET /api/ml` | ML self-learning engine status |
| `GET /api/mutes` | List muted IPs |
| `POST /api/mutes/<ip>` | Mute/unmute an IP |
| `POST /api/feedback` | Submit rule classification feedback |
| `GET /api/opnsense` | OPNsense API proxy |
| `GET /api/interfaces` | OPNsense interface status |
| `GET /api/wan` | WAN gateway status |
| `GET /api/dhcpd` | DHCP lease info |
| `GET /api/filter` | Firewall filter status |
| `GET /api/routing` | Routing/gateway status |
| `GET /api/heartbeat` | Heartbeat/ping |

## Machine Learning Self-Learning Engine

The agent includes a 5-phase self-learning ML engine that evolves over time:

### Phase 1: Feedback Loop
Users classify rules as correct/incorrect. The system learns from this feedback.

### Phase 2: Per-Rule Baselines
Each rule develops its own statistical baseline (mean, variance, port diversity, destination diversity, pass/block ratio).

### Phase 3: Temporal Patterns
The system learns when traffic is normal vs abnormal based on time of day, day of week, and historical patterns.

### Phase 4: Active Learning Queue
Rules that need human feedback are queued for review. The system prioritizes rules with high uncertainty.

### Phase 5: Threshold Auto-Tuning
The system automatically adjusts anomaly detection thresholds based on feedback, reducing false positives over time.

## Reverse DNS Resolver

The agent includes a reverse DNS resolver that translates IP addresses to hostnames:

- **Static hostname mapping** — Pre-configured internal IPs (opnsense, hassio, anomaly-agent)
- **Redis caching** — Persistent hostname cache with configurable TTL
- **DNS resolution** — Falls back to OPNsense DNS server (Unbound)
- **In-memory cache** — Fast lookup for recently resolved IPs
- **Custom hostname map file** — Set `REVERSE_DNS_STATIC_MAP=/app/agent_data/hosts.txt` for additional mappings

## Configuration

### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `OPN_HOST` | `192.168.1.1` | OPNsense firewall IP/hostname |
| `OPN_PORT` | `6666` | OPNsense API port (custom port) |
| `OPN_API_KEY` | *(required)* | OPNsense API key |
| `OPN_API_SECRET` | *(required)* | OPNsense API secret |
| `OPN_VERIFY_SSL` | `false` | Verify OPNsense SSL certificate |
| `DISCORD_TOKEN` | *(required)* | Discord bot token |
| `DISCORD_CHANNEL_ID` | *(required)* | Discord channel ID for alerts |
| `CHAT_PORT` | `8765` | HTTP port for chat commands and web dashboard |
| `SYSLOG_ENABLED` | `false` | Enable built-in syslog listener |
| `SYSLOG_UDP_PORT` | `1514` | UDP port to receive syslog |
| `APPRISE_URLS` | `(none)` | Comma-separated Apprise notification URIs (optional multi-platform alerts) |
| `SYSLOG_BIND` | `0.0.0.0` | Network interface for syslog UDP listener (set to specific IP to restrict) |
| `DASHBOARD_BIND` | `0.0.0.0` | Network interface for dashboard API (set to `127.0.0.1` for localhost-only) |
| `WAN_IP_MIN_EVENTS` | `10` | Minimum events before an external IP gets tracked |
| `MAX_WAN_IPS` | `10000` | Maximum number of external WAN IPs to track |
| `OWN_WAN_IPS` | *(required)* | Your own WAN IP addresses — comma-separated |
| `LAN_IPS` | `192.168.1.0/24,10.0.0.0/8` | Known LAN IP ranges |
| `VPN_IPS` | `10.80.80.0/24,10.11.12.0/24` | VPN networks (OpenVPN, WireGuard) |
| `REVERSE_DNS_ENABLED` | `false` | Enable reverse DNS resolution |
| `REVERSE_DNS_SERVER` | `192.168.1.1` | DNS server for reverse lookups |
| `REVERSE_DNS_CACHE_TTL` | `3600` | Redis cache TTL for DNS lookups (seconds) |
| `REVERSE_DNS_STATIC_MAP` | `None` | Path to static hostname map file |
| `VLLM_BASE_URL` | `None` | vLLM inference server URL (optional) |
| `VLLM_MODEL` | `QuantTrio/Qwen3.6-35B-A3B-AWQ` | vLLM model name |
| `DB_HOST` | `localhost` | PostgreSQL database host |
| `DB_PORT` | `5432` | PostgreSQL database port |
| `DB_NAME` | `opnsense` | PostgreSQL database name |
| `DB_USER` | `opnsense` | PostgreSQL database user |
| `DB_PASSWORD` | `opnsense` | PostgreSQL database password |
| `REDIS_URL` | `redis://redis:6379/0` | Redis connection URL |
| `AUTH_THRESHOLD` | `5` | Minimum events for auth anomaly detection |
| `AUTH_WINDOW` | `60` | Auth detection window in minutes |
| `BATCH_SIZE` | `100` | Batch size for processing events |
| `DEDUP_SECONDS` | `5` | Deduplication window in seconds |
| `GEO_ANOMALY_THRESHOLD` | `10` | Minimum events for geo anomaly detection |
| `LEARN_INTERVAL` | `300` | Learning interval in seconds |
| `POLL_INTERVAL` | `10` | OPNsense API poll interval in seconds |
| `PORTSCAN_THRESHOLD` | `10` | Port scan detection threshold |
| `PORTSCAN_WINDOW` | `60` | Port scan detection window in minutes |
| `STAT_DEVIATION` | `3.0` | Standard deviations for anomaly detection |
| `STAT_WINDOW` | `3600` | Statistical analysis window in seconds |
| `STAT_ZSCORE` | `3.0` | Z-score threshold for anomaly detection |
| `SYN_THRESHOLD` | `50` | SYN flood detection threshold |
| `SYN_WINDOW` | `60` | SYN detection window in minutes |
| `CUSTOM_INTERFACES` | `None` | Custom interface-to-class mapping |

### ML Threshold Configuration

For non-secret configuration (learning thresholds, detection options):

- `STAT_WINDOW` — Minutes for statistical pattern tracking (default: 3600 seconds = 60 minutes)
- `STAT_DEVIATION` — Standard deviations for anomaly detection (default: 3.0)
- `STAT_ZSCORE` — Z-score threshold for anomaly detection (default: 3.0)
- `PORTSCAN_THRESHOLD` — Number of unique destinations to flag a port scan (default: 10)
- `PORTSCAN_WINDOW` — Port scan detection window in minutes (default: 60)
- `AUTH_THRESHOLD` — Minimum events for auth anomaly detection (default: 5)
- `AUTH_WINDOW` — Auth detection window in minutes (default: 60)
- `SYN_THRESHOLD` — SYN flood detection threshold (default: 50)
- `SYN_WINDOW` — SYN detection window in minutes (default: 60)

## Data Directory (`agent_data/`)

| File | Purpose |
|---|---|
| `syslog_events.jsonl` | All parsed firewall events (append-only, grows over time) |
| `state.json` | Agent state (processed events, counters, learned patterns) |
| `mutes.json` | Muted IPs and their expiration times |
| `jsonl_read_marker.json` | Read position in JSONL file for the agent |
| `anomaly_log.jsonl` | Logged anomalies |

These files are gitignored. The data directory is designed to be volume-mounted so data persists across container restarts.

## Docker Reference

### Stop/Restart

```bash
# Full stack
docker compose down
docker compose up -d

# Individual service
docker stop anomaly-agent
docker start anomaly-agent
```

### View Logs

```bash
docker logs anomaly-agent
docker logs -f anomaly-agent    # Follow mode
```

### Reset State

Delete `agent_data/state.json` to reset learned patterns:

```bash
rm agent_data/state.json
docker restart anomaly-agent
```

### Using Pre-built Images

To deploy from GHCR instead of building locally:

```bash
# In .env
AGENT_IMAGE=ghcr.io/timolow/opnsense-anomaly-agent:latest

# Restart
docker compose up -d
```

## CI/CD Pipeline

The project includes a comprehensive GitHub Actions CI pipeline:

- **Test Suite** — 172 tests across all modules (adaptive_parser, reverse_dns, ml_learning, rule_classify, statistical_model, apprise_notifier, integration)
- **Docker Build** — Builds and pushes multi-platform Docker images to GHCR
- **CodeQL Analysis** — Automated security scanning (binding, permissions, etc.)
- **Every Push** — All tests run automatically on every commit to `master`
- **Tag Releases** — Docker images are tagged with commit SHA and `latest`

## Requirements

- Python 3.11+ (for standalone syslog listener)
- Docker and Docker Compose (for the agent)
- Discord bot token ([create one here](https://discord.com/developers/applications))
- OPNsense firewall with syslog enabled

## Dependencies

```
requests>=2.32.4
discord.py>=2.4.0
numpy>=2.0.0
psycopg2-binary>=2.9.0
maxminddb>=2.0.0
python-dotenv>=1.0.0
dnspython>=2.6.0
redis>=5.0.0
apprise>=1.9.0
```

Install for local development:

```bash
pip install -r requirements.txt
```

## License

MIT