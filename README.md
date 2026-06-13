# OPNsense Anomaly Detection Agent

A lightweight anomaly detection agent that monitors OPNsense firewall logs via UDP syslog, learns normal traffic patterns, and sends Discord alerts for suspicious activity.

## Architecture

```
OPNsense Firewall
       |
       | (UDP syslog on port 1514)
       v
┌─────────────────┐
│ syslog_listener │ ← Runs on host machine
│    (Python)     │    Parses filterlog CSV, writes JSONL
└────────┬────────┘
         |
         | (syslog_events.jsonl)
         v
┌─────────────────┐
│  anomaly agent  │ ← Runs in Docker
│    (Python)     │    Detects anomalies, sends alerts
└────────┬────────┘
         |
         | (Discord API)
         v
┌─────────────────┐
│    Discord      │    Alerts + chat commands
└─────────────────┘
```

### Two Components

| Component | Where | What |
|---|---|---|
| `syslog_listener.py` | Host machine | Listens for UDP syslog on port 1514, parses OPNsense filterlog CSV, writes events to `agent_data/syslog_events.jsonl` |
| `agent.py` | Docker container | Reads JSONL events, applies ML-based anomaly detection, sends Discord alerts and responds to chat commands |

### Detection Capabilities

- **New source IPs** — External addresses seen for the first time
- **Unusual ports** — Traffic to ports not seen in recent history
- **High event rates** — Unusually high volume of firewall events from a single source
- **Port scans** — Single source connecting to many different destinations
- **Data exfiltration indicators** — Outbound connections to unusual destinations

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

**Option A: Environment variables (recommended for Docker)**

Edit `.env` with your credentials:

```bash
OPN_HOST=192.168.1.1
OPN_PORT=6666
OPN_API_KEY=your_api_key_here
OPN_API_SECRET=your_api_secret_here
DISCORD_TOKEN=your_discord_bot_token_here
DISCORD_CHANNEL_ID=your_channel_id_here
CHAT_PORT=8765
```

**Option B: config.json** (for local runs and Discord fallback)

Edit `config.json` — replace placeholder values. Note: this file is gitignored, so secrets never get committed.

### 3. Configure OPNsense to Send Syslog

On your OPNsense firewall, configure syslog output:

1. **System > Settings > Log Settings > Log Targets** — Add a new target
2. **Remote Log Host**: Your Mac's IP address
3. **Protocol**: UDP
4. **Port**: 1514
5. **Log Level**: Select at minimum `Filterlog`
6. Save and apply

### 4. Run the Syslog Listener (Host)

```bash
python3 syslog_listener.py
```

Or with environment variables:

```bash
SYSLOG_UDP_PORT=1514 DATA_DIR=./agent_data python3 syslog_listener.py
```

The listener writes parsed events to `agent_data/syslog_events.jsonl`.

### 5. Run the Anomaly Agent (Docker)

```bash
# Build image
docker build -t opnsense-anomaly-agent .

# Run container
docker run -d --name anomaly-agent --network host \
  -v "$(pwd)/agent_data:/app/agent_data" \
  --env-file .env \
  opnsense-anomaly-agent
```

Or without `.env` file — pass env vars directly:

```bash
docker run -d --name anomaly-agent --network host \
  -v "$(pwd)/agent_data:/app/agent_data" \
  -e OPN_HOST=192.168.1.1 \
  -e OPN_API_KEY=your_key \
  -e OPN_API_SECRET=your_secret \
  -e DISCORD_TOKEN=your_token \
  -e DISCORD_CHANNEL_ID=your_channel_id \
  opnsense-anomaly-agent
```

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
| `SYSLOG_UDP_PORT` | `1514` | UDP port to receive syslog |
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
docker stop anomaly-agent
docker rm anomaly-agent
# Then run again with docker run ...
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

- Python 3.9+
- Docker (for the agent container)
- Discord bot token ([create one here](https://discord.com/developers/applications))
- OPNsense firewall with syslog enabled

## Dependencies

```
requests==2.31.0
discord.py==2.3.2
numpy<2.0
```

Install for local development:

```bash
pip install -r requirements.txt
```

## License

MIT
