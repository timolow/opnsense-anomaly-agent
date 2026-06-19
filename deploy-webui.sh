#!/bin/bash
# Deploy React WebUI + updated server to remote host

set -e

REMOTE_USER="root"
REMOTE_HOST="192.168.1.50"
REMOTE_DIR="/opt/opnsense-anomaly-agent"

echo "=== Building Docker image ==="
cd /Users/timolow/opnsense-anomaly-agent
docker build -t ghcr.io/timolow/opnsense-anomaly-agent:latest .

echo "=== Pushing to GHCR ==="
docker push ghcr.io/timolow/opnsense-anomaly-agent:latest

echo "=== Pulling on remote ==="
ssh ${REMOTE_USER}@${REMOTE_HOST} "cd ${REMOTE_DIR} && docker compose pull && docker compose up -d"

echo "=== Deploy complete ==="
