# ---------- WebUI build stage ----------
FROM node:20-alpine AS webui-build

WORKDIR /build
COPY webui/package.json webui/package-lock.json ./
RUN npm ci

COPY webui/ .
RUN npm run build

# ---------- Production stage ----------
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
COPY rule_classify.py .
COPY service_monitor.py .
COPY apprise_notifier.py .
COPY server.py .
COPY app.html .
COPY ml_learning.py .
COPY wan_flap_detector.py .
COPY zenarmor_classifier.py .
COPY ids_signature_analyzer.py .
COPY nginx_monitor.py .

# Copy new modules
COPY graylog_training_extractor.py .
COPY graylog_training_pipeline.py .
COPY baseline_engine.py .
COPY threat_engine.py .
COPY dashboard_api.py .

# Copy built webui from build stage
COPY --from=webui-build /build/dist webui/dist

# Create data directory
RUN mkdir -p /app/agent_data

EXPOSE 1514/udp
EXPOSE 8765/tcp
EXPOSE 8000/tcp

CMD ["python3", "agent.py"]