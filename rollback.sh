#!/usr/bin/env bash
#
# rollback.sh — Rollback to the previous agent version
#
# Usage:
#   ./rollback.sh          # Rollback to previous version (from deploy_state.json)
#   ./rollback.sh IMAGE    # Rollback to a specific image tag
#
# This is the emergency brake — fast, no build step, just swap containers.
#

set -euo pipefail

# ── Configuration ──────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

COMPOSE_FILE="docker-compose.yml"
PROJECT="opnsense-anomaly-agent"
AGENT_SERVICE="agent"
CONTAINER_NAME="anomaly-agent"
HEALTH_URL="http://localhost:8766/api/health"
DEPLOY_STATE_FILE="./deploy_state.json"

# Timeouts
HEALTH_CHECK_RETRIES=30
HEALTH_CHECK_INTERVAL=2
GRACEFUL_STOP_TIMEOUT=30

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# ── Helpers ────────────────────────────────────────────────────────
log_info()  { echo -e "${CYAN}[rollback]${NC} $*"; }
log_ok()    { echo -e "${GREEN}[✓]${NC} $*"; }
log_warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
log_err()   { echo -e "${RED}[✗]${NC} $*" >&2; }

check_health() {
    local retries=0
    while [ $retries -lt "$HEALTH_CHECK_RETRIES" ]; do
        local response
        if response=$(curl -fs "$HEALTH_URL" 2>/dev/null); then
            local status
            status=$(echo "$response" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status','unknown'))" 2>/dev/null || echo "unknown")
            if [[ "$status" == "healthy" || "$status" == "active" || "$status" == "cold-start" ]]; then
                return 0
            fi
        fi
        retries=$((retries + 1))
        sleep "$HEALTH_CHECK_INTERVAL"
    done
    return 1
}

# Update AGENT_IMAGE in .env file
set_agent_image() {
    local new_image="$1"
    local env_file="${SCRIPT_DIR}/.env"

    if [ ! -f "$env_file" ]; then
        log_err ".env file not found at $env_file"
        exit 1
    fi

    python3 -c "
import re
with open('$env_file', 'r') as f:
    content = f.read()
if re.search(r'^AGENT_IMAGE=', content, re.MULTILINE):
    content = re.sub(r'^AGENT_IMAGE=.*$', 'AGENT_IMAGE=$new_image', content, flags=re.MULTILINE)
else:
    content = content.rstrip('\n') + '\nAGENT_IMAGE=$new_image\n'
with open('$env_file', 'w') as f:
    f.write(content)
"
    log_info "Updated AGENT_IMAGE=$new_image in .env"
}

# ── Main rollback flow ─────────────────────────────────────────────
main() {
    local target_image="${1:-}"

    echo ""
    log_info "═══════════════════════════════════════════════════════"
    log_info "  OPNsense Anomaly Agent — Rollback"
    log_info "═══════════════════════════════════════════════════════"
    echo ""

    # Determine target image
    if [ -z "$target_image" ]; then
        if [ ! -f "$DEPLOY_STATE_FILE" ]; then
            log_err "No deploy state found at $DEPLOY_STATE_FILE"
            log_info "Run ./deploy.sh first to create deploy state, or specify an image:"
            log_info "  ./rollback.sh ${PROJECT}:abc1234"
            exit 1
        fi

        target_image=$(python3 -c "import json; print(json.load(open('$DEPLOY_STATE_FILE'))['previous_image'])")
        local current_image
        current_image=$(python3 -c "import json; print(json.load(open('$DEPLOY_STATE_FILE'))['current_image'])")
        log_info "Rolling back: $current_image → $target_image"
    else
        log_info "Rolling back to specified image: $target_image"
    fi

    # Verify the image exists
    if ! docker image inspect "$target_image" >/dev/null 2>&1; then
        log_err "Image $target_image not found locally."
        log_info "Available images:"
        docker images --format "  {{.Repository}}:{{.Tag}} ({{.CreatedSince}})" | grep "$PROJECT" | head -10
        exit 1
    fi
    log_ok "Target image verified: $target_image"

    # Stop current container
    log_info "Stopping current agent..."
    if docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
        docker stop -t "$GRACEFUL_STOP_TIMEOUT" "$CONTAINER_NAME" 2>/dev/null || true
        docker rm "$CONTAINER_NAME" 2>/dev/null || true
        log_ok "Current container stopped"
    else
        log_warn "No running agent container found"
    fi

    # Update .env and start rollback image
    log_info "Starting rollback image..."
    set_agent_image "$target_image"
    docker compose up -d "$AGENT_SERVICE" 2>&1 | tail -3

    # Health check
    log_info "Waiting for health check..."
    if check_health; then
        log_ok "Rollback successful! Agent is healthy."

        # Update deploy state
        local previous_previous=""
        if [ -f "$DEPLOY_STATE_FILE" ]; then
            previous_previous=$(python3 -c "import json; print(json.load(open('$DEPLOY_STATE_FILE')).get('previous_image',''))" 2>/dev/null || echo "")
        fi

        local timestamp
        timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
        cat > "$DEPLOY_STATE_FILE" <<EOF
{
    "timestamp": "$timestamp",
    "commit_sha": "rollback",
    "current_image": "$target_image",
    "previous_image": "${previous_previous:-none}"
}
EOF
    else
        log_err "Rollback container failed health check!"
        log_info "Manual intervention required. Check container logs:"
        log_info "  docker logs $CONTAINER_NAME"
        exit 1
    fi

    echo ""
    log_ok "═══════════════════════════════════════════════════════"
    log_ok "  Rollback complete! Running: $target_image"
    log_ok "═══════════════════════════════════════════════════════"
    echo ""
}

main "${1:-}"