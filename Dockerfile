FROM python:3.9-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy agent files only (no secrets)
COPY agent.py .
COPY syslog_listener.py .

# Create data directory
RUN mkdir -p /app/agent_data

# Expose ports
EXPOSE 1514/udp
EXPOSE ${CHAT_PORT:-8765}/tcp

# Default: run the anomaly agent
# Override with: docker run ... syslog_listener.py
CMD ["python3", "agent.py"]
