#!/bin/bash
# Deploy pfelk on remote host (192.168.99.12)
# Run: ./deploy-pfelk.sh <remote_user>@<remote_host>

set -e

REMOTE="${1:-tim@192.168.1.50}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "=== Deploying pfelk to ${REMOTE} ==="

# ── Step 1: Create remote directory ──
ssh "${REMOTE}" "mkdir -p ~/pfelk && mkdir -p ~/pfelk/data/esdata"

# ── Step 2: Copy configuration files ──
echo "Uploading configuration files..."
scp "${SCRIPT_DIR}/docker-compose.yml" "${REMOTE}:~/pfelk/docker-compose.yml"
scp "${SCRIPT_DIR}/.env" "${REMOTE}:~/pfelk/.env"

# ── Step 3: Copy Logstash pipeline ──
ssh "${REMOTE}" "mkdir -p ~/pfelk/pfelk-config/logstash/pipeline"
ssh "${REMOTE}" "mkdir -p ~/pfelk/pfelk-config/logstash/patterns"
scp "${SCRIPT_DIR}/pfelk-config/logstash/pipeline/pfelk.conf" "${REMOTE}:~/pfelk/pfelk-config/logstash/pipeline/pfelk.conf"
scp "${SCRIPT_DIR}/pfelk-config/logstash/patterns/pfelk.grok" "${REMOTE}:~/pfelk/pfelk-config/logstash/patterns/pfelk.grok"

# ── Step 4: Set vm.max_map_count if needed ──
ssh "${REMOTE}" "sysctl -w vm.max_map_count=262144 || true"

# ── Step 5: Verify files ──
echo "Verifying uploaded files..."
ssh "${REMOTE}" "ls -la ~/pfelk/ && ls -la ~/pfelk/pfelk-config/logstash/pipeline/ && ls -la ~/pfelk/pfelk-config/logstash/patterns/"

# ── Step 6: Start pfelk ──
echo "Starting pfelk stack..."
ssh "${REMOTE}" "cd ~/pfelk && docker compose up -d"

# ── Step 7: Wait for services ──
echo "Waiting for services to start (60s)..."
sleep 60

# ── Step 8: Check status ──
echo "=== pfelk status ==="
ssh "${REMOTE}" "cd ~/pfelk && docker compose ps"

# ── Step 9: Test Elasticsearch ──
echo "=== Elasticsearch test ==="
ssh "${REMOTE}" "curl -s -u elastic:pfelk_...n http://localhost:9200/ | head -20"

echo "=== pfelk deployment complete ==="
echo "Kibana: http://192.168.99.12:5601"
echo "Elasticsearch: http://192.168.99.12:9200"
echo "Logstash syslog input: 192.168.99.12:5140 (UDP/TCP)"
