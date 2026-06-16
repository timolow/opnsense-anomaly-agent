# OPNsense Anomaly Detection Agent
# Multi-purpose Docker image: agent, syslog_listener, or vLLM client

# ---------- Build stage ----------
FROM python:3.11-slim AS base

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy all source files
COPY agent.py .
COPY syslog_listener.py .
COPY adaptive_parser.py .
COPY eventdb.py .
COPY attack_detectors.py .
COPY statistical_model.py .
COPY geo_lookup.py .
COPY discord_bot.py .
COPY reverse_dns.py .
COPY network_classifier.py .
COPY state_persistence.py .
COPY rule_classifier.py .
COPY system_log_classifier.py .
COPY service_monitor.py .
COPY server.py .
COPY app.html .

# Create data directory
RUN mkdir -p /app/agent_data

# ---------- Default: run anomaly agent ----------
# Override CMD at runtime for different services:
#   docker run anomaly-agent python3 agent.py
#   docker run anomaly-agent python3 syslog_listener.py
#   docker run anomaly-agent python3 -m http.server 8080  (debug)

EXPOSE 1514/udp
EXPOSE 8765/tcp
EXPOSE 8000/tcp

CMD ["python3", "agent.py"]
