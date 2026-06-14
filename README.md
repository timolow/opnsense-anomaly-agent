# OPNsense Anomaly Detection Agent

A lightweight anomaly detection agent that monitors OPNsense firewall logs, learns normal traffic patterns, and sends Discord alerts for suspicious activity.

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
│ anomaly agent (Docker)  │    Detects anomalies, sends alerts
│                         │    Responds to chat commands
└────────┬────────────────┘
         |
         | (Discord API)
         v
┌─────────────────────────┐
│    Discord              │    Alerts + chat commands
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

## Quick Start

### 1. Clone and Configure

```bash
git clone https://github.com/yourusername/opnsense-anomaly-agent.git
cd opnsense-anomaly-agent

# Copy example configs
cp config.example.json config.json
cp .env.example .env
```

### 2. Configure Secrets

Edit `.env` with your credentials:

```bash
OPN_HOST=192.168.1.1
OPN_PORT=6666
OPN_API_KEY=your_api_key_here
OPN_API_SECRET=your_api_secret_here
DISCORD_TOKEN=your_discord_bot_token_here
DISCORD_CHANNEL_ID=your_channel_id_here
CHAT_PORT=8765
SYSLOG_UDP_PORT=1514
```

### 3. Configure OPNsense to Send Syslog

On your OPNsense firewall, configure syslog output:

1. **System > Settings > Log Settings > Log Targets** — Add a new target
2. **Remote Log Host**: Your machine's IP address (where syslog listener will run)
3. **Protocol**: UDP
4. **Port**: 1514 (or the port you set in `SYSLOG_UDP_PORT`)
5. **Log Level**: Select at minimum `Filterlog`
6. Save and apply

---

### Option A: Single Container (Recommended)

Everything runs in one Docker Compose setup. The agent embeds the syslog listener internally.

```bash
# Start everything
sudo docker compose up -d
```

This starts:
- PostgreSQL for persistent event storage
- The anomaly agent (which includes the built-in syslog listener on UDP port 1514)

No separate syslog listener process needed.

### Option B: Standalone Syslog Listener + Docker Agent

Run the syslog listener as a standalone script and feed events to the Docker agent via shared JSONL file.

**1. Run the syslog listener (any machine that can receive UDP):**

```bash
python3 syslog_listener.py
```

Or with environment variables:

```bash
SYSLOG_UDP_PORT=1514 DATA_DIR=./agent_data python3 syslog_listener.py
```

This writes parsed events to `agent_data/syslog_events.jsonl`.

**2. Run the anomaly agent in Docker:**

```bash
# Build image
docker build -t opnsense-anomaly-agent .

# Run container — mount the same agent_data directory
docker run -d --name anomaly-agent --network host \
  -v "$(pwd)/agent_data:/app/agent_data" \
  --env-file .env \
  opnsense-anomaly-agent
```

The agent reads from the shared JSONL file.

---

## Chat Commands

The agent runs a local HTTP server on port 8765 by default. Send commands from any Discord channel:

| Command | Description |
|---|---|
| `!status` | Show current agent status (events processed, anomalies detected, uptime) |
| `!stats` | Show learned pattern statistics |
| `!topblocked` | Show top blocked source IPs |
| `!help` | Show all available commands |

## Configuration

### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `OPN_HOST` | `192.168.1.1` | OPNsense firewall IP/hostname |
| `OPN_PORT` | `6666` | OPNsense API port (custom port) |
| `OPN_API_KEY` | *(required)* | OPNsense API key |
| `OPN_API_SECRET` | *(required)* | OPNsense API secret |
| `DISCORD_TOKEN` | *(required)* | Discord bot token |
| `DISCORD_CHANNEL_ID` | *(required)* | Discord channel ID for alerts |
| `CHAT_PORT` | `8765` | HTTP port for chat commands |
| `SYSLOG_UDP_PORT` | `1514` | UDP port to receive syslog (standalone mode) |
| `DATA_DIR` | `./agent_data` | Directory for JSONL and learned patterns |
| `JSONL_PATH` | `./agent_data/syslog_events.jsonl` | Path to JSONL event file |
| `LOG_LEVEL` | `INFO` | Logging level (DEBUG, INFO, WARNING, ERROR) |

### config.json Settings

For non-secret configuration (learning thresholds, detection options):

- `learning.short_term_window` — Minutes for short-term pattern tracking (default: 60)
- `learning.anomaly_threshold` — Sensitivity 0-1, higher = fewer false positives (default: 0.75)
- `anomaly.port_scan_threshold` — Number of unique destinations to flag a port scan (default: 10)
- `anomaly.rate_threshold_per_minute` — Event rate that triggers a warning (default: 100)

## Docker Reference

### Stop/Restart

```bash
# For single-container mode:
docker compose down
docker compose up -d

# For standalone + agent mode:
docker stop anomaly-agent
docker rm anomaly-agent
```

### View Logs

```bash
docker logs anomaly-agent
docker logs -f anomaly-agent    # Follow mode
```

### Reset State

Delete `agent_data/learned_patterns.json` to reset learned patterns:

```bash
rm agent_data/learned_patterns.json
docker restart anomaly-agent
```

## Data Directory (`agent_data/`)

| File | Purpose |
|---|---|
| `syslog_events.jsonl` | All parsed firewall events (append-only, grows over time) |
| `learned_patterns.json` | Learned traffic patterns (IP pairs, ports, rates) |
| `jsonl_read_marker.json` | Read position in JSONL file for the agent |
| `syslog_listener.log` | Runtime log from the syslog listener |
| `anomaly_log.jsonl` | Logged anomalies |

These files are gitignored. The data directory is designed to be volume-mounted so data persists across container restarts.

## Requirements

- Python 3.9+ (for standalone syslog listener)
- Docker and Docker Compose (for the agent)
- Discord bot token ([create one here](https://discord.com/developers/applications))
- OPNsense firewall with syslog enabled

## Dependencies

```
requests==2.31.0
discord.py==2.3.2
numpy<2.0
psycopg2-binary
maxminddb
python-dotenv
```

Install for local development:

```bash
pip install -r requirements.txt
```

## License

MIT
