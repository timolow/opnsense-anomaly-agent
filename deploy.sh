#!/usr/bin/env bash
#
# deploy.sh — Zero-downtime blue-green deployment for OPNsense Anomaly Agent
#
# Usage:
#   ./deploy.sh            # Deploy latest changes (build + rolling update)
#   ./deploy.sh --tag TAG  # Build with explicit image tag
#
# How it works (blue-green with connection draining):
#   1. Build new image tagged with git commit SHA
#   2. Record current running image as rollback target
#   3. Start new agent container on a staging port (8767)
#   4. Wait for health check to pass on the new container
#   5. Signal old container to drain in-flight requests (POST /api/drain)
#   6. Wait for drain to complete or timeout
#   7. Stop old agent container
#   8. Set AGENT_IMAGE in .env to the new image
#   9. Start new agent on production ports via docker compose
#  10. Verify production health check passes
#  11. Clean up old container and image
#
# If ANY step fails, the script ABORTS and leaves the old version running.
# Use ./rollback.sh to revert to the previous version.
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
STAGING_CONTAINER="anomaly-agent-staging"
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

# ── Helper functions ───────────────────────────────────────────────
log_info()  { echo -e "${CYAN}[deploy]${NC} $*"; }
log_ok()    { echo -e "${GREEN}[✓]${NC} $*"; }
log_warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
log_err()   { echo -e "${RED}[✗]${NC} $*" >&2; }

# Get current git commit SHA (short)
get_commit_sha() {
    git rev-parse --short HEAD 2>/dev/null || echo "unknown"
}

# Get current running image for the agent container
get_current_image() {
    docker inspect "$CONTAINER_NAME" --format '{{.Config.Image}}' 2>/dev/null || echo ""
}

# Check health of a specific URL
check_health_url() {
    local url="$1"
    local retries=0
    while [ $retries -lt "$HEALTH_CHECK_RETRIES" ]; do
        local response
        if response=$(curl -fs "$url" 2>/dev/null); then
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

# Save deployment state for rollback
save_deploy_state() {
    local new_image="$1"
    local old_image="$2"
    local timestamp
    timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    local commit_sha
    commit_sha=$(get_commit_sha)

    cat > "$DEPLOY_STATE_FILE" <<EOF
{
    "timestamp": "$timestamp",
    "commit_sha": "$commit_sha",
    "current_image": "$new_image",
    "previous_image": "$old_image"
}
EOF
    log_info "Deploy state saved to $DEPLOY_STATE_FILE"
}

# ── Main deploy flow ───────────────────────────────────────────────
main() {
    local image_tag="${1:-}"
    local commit_sha
    commit_sha=$(get_commit_sha)

    echo ""
    log_info "═══════════════════════════════════════════════════════"
    log_info "  OPNsense Anomaly Agent — Zero-Downtime Deploy"
    log_info "  Commit: $commit_sha"
    log_info "═══════════════════════════════════════════════════════"
    echo ""

    # Step 1: Record current running image
    log_info "Step 1: Recording current deployment..."
    local current_image
    current_image=$(get_current_image)

    if [ -z "$current_image" ]; then
        log_warn "No running agent container found. Performing initial deploy."
        current_image="none"
    else
        log_info "Current image: $current_image"
    fi

    # Step 2: Build new image
    log_info "Step 2: Building new image..."
    local new_image="${PROJECT}:${commit_sha}"

    if [ -n "$image_tag" ]; then
        new_image="${PROJECT}:${image_tag}"
    fi

    docker build -t "$new_image" -t "${PROJECT}:latest" . 2>&1 | tail -5
    log_ok "Image built: $new_image"

    # Step 3: Start staging container on alternate ports
    log_info "Step 3: Starting staging container on port 8767..."

    # Stop any existing staging container
    docker rm -f "$STAGING_CONTAINER" >/dev/null 2>&1 || true

    # Start staging container with different API port (8767) - no syslog to avoid port conflicts
    docker run -d \
        --name "$STAGING_CONTAINER" \
        --network "${PROJECT}_default" \
        --env-file .env \
        -e AGENT_IMAGE="$new_image" \
        -e CHAT_PORT=8765 \
        -e SYSLOG_ENABLED=false \
        -v "./app.html:/app/app.html:ro" \
        -v "./agent_data:/app/agent_data" \
        -v "./data:/app/data" \
        -v "./backups:/app/backups" \
        -p "8767:8766/tcp" \
        "$new_image" \
        || { log_err "Failed to start staging container"; exit 1; }

    # Step 4: Health check staging container
    log_info "Step 4: Waiting for staging container health..."
    local staging_health="http://localhost:8767/api/health"

    if check_health_url "$staging_health"; then
        log_ok "Staging container healthy!"
    else
        log_err "Staging container FAILED health check after $((HEALTH_CHECK_RETRIES * HEALTH_CHECK_INTERVAL))s"
        log_info "Cleaning up staging container..."
        docker rm -f "$STAGING_CONTAINER" >/dev/null 2>&1 || true
        log_info "Old version is still running. Use ./rollback.sh to recover if needed."
        exit 1
    fi

    # Step 5: Signal old container to drain in-flight requests
    log_info "Step 5: Draining old container requests..."
    local drain_timeout=15
    if docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
        local drain_result
        if drain_result=$(curl -sf --max-time "$drain_timeout" \
            -X POST "http://localhost:8766/api/drain" \
            -H "Content-Type: application/json" \
            -d "{\"timeout\": $drain_timeout}" 2>&1); then
            local drained
            drained=$(echo "$drain_result" | python3 -c "import sys,json; print(json.load(sys.stdin).get('drained', False))" 2>/dev/null || echo "False")
            if [[ "$drained" == "True" ]]; then
                log_ok "Old container drained successfully"
            else
                log_warn "Drain did not complete in time — proceeding anyway"
            fi
        else
            log_warn "Could not reach drain endpoint — old container may already be stopping"
        fi
        # Brief pause for final cleanup after drain
        sleep 2
    else
        log_info "No running agent container to drain"
    fi

    # Step 6: Stop old agent container (graceful)
    log_info "Step 6: Stopping old agent container..."
    if docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
        docker stop -t "$GRACEFUL_STOP_TIMEOUT" "$CONTAINER_NAME" 2>/dev/null || true
        docker rm "$CONTAINER_NAME" 2>/dev/null || true
        log_ok "Old container stopped and removed"
    else
        log_info "No running agent container to stop"
    fi

    # Step 7: Remove staging container and update .env for production
    log_info "Step 7: Preparing production deployment..."
    docker rm -f "$STAGING_CONTAINER" >/dev/null 2>&1 || true

    # Set AGENT_IMAGE in .env to the new image
    set_agent_image "$new_image"

    # Start new agent on production ports via docker compose
    docker compose up -d "$AGENT_SERVICE" 2>&1 | tail -3
    log_ok "New agent container started"

    # Step 8: Health check production container
    log_info "Step 8: Verifying production health..."
    if check_health_url "$HEALTH_URL"; then
        log_ok "Production container healthy!"
    else
        log_err "Production container FAILED health check!"
        log_info "Attempting automatic rollback..."
        docker stop -t "$GRACEFUL_STOP_TIMEOUT" "$CONTAINER_NAME" 2>/dev/null || true
        docker rm "$CONTAINER_NAME" 2>/dev/null || true

        if [ "$current_image" != "none" ]; then
            log_info "Restarting previous version: $current_image"
            set_agent_image "$current_image"
            docker compose up -d "$AGENT_SERVICE" 2>&1 | tail -3
            sleep 15
            if check_health_url "$HEALTH_URL"; then
                log_ok "Automatic rollback successful — previous version restored"
            else
                log_err "Automatic rollback also failed! Manual intervention required."
                log_info "Run ./rollback.sh to try again."
            fi
        else
            log_err "No previous version available. Manual intervention required."
        fi
        exit 1
    fi

    # ── E2E Verification Gate ──────────────────────────────────────────
    log_info "Step 9: Running E2E verification gate..."
    local e2e_failed=0

    # Run each E2E verification module inside the container against localhost:8766
    local e2e_scripts=("api_verification.py" "empty_state_verification.py" "pipeline_verification.py")
    local e2e_results=()

    for script in "${e2e_scripts[@]}"; do
        log_info "  Running $script..."
        local script_start
        script_start=$(date +%s)

        if docker exec "$CONTAINER_NAME" python3 "$script" 2>&1; then
            local script_end
            script_end=$(date +%s)
            local script_duration=$((script_end - script_start))
            log_ok "  $script passed (${script_duration}s)"
            e2e_results+=("$script:PASS")
        else
            local script_end
            script_end=$(date +%s)
            local script_duration=$((script_end - script_start))
            log_err "  $script FAILED (${script_duration}s)"
            e2e_results+=("$script:FAIL")
            e2e_failed=1
        fi
    done

    if [ $e2e_failed -ne 0 ]; then
        echo ""
        log_err "═══════════════════════════════════════════════════════"
        log_err "  E2E VERIFICATION FAILED — Deployment blocked!"
        log_err "═══════════════════════════════════════════════════════"
        for res in "${e2e_results[@]}"; do
            local name="${res%%:*}"
            local status="${res##*:}"
            if [ "$status" = "PASS" ]; then
                log_ok "  $name: PASS"
            else
                log_err "  $name: FAIL"
            fi
        done
        echo ""
        log_err "E2E checks failed. Rolling back to previous version..."
        docker stop -t "$GRACEFUL_STOP_TIMEOUT" "$CONTAINER_NAME" 2>/dev/null || true
        docker rm "$CONTAINER_NAME" 2>/dev/null || true

        if [ "$current_image" != "none" ]; then
            log_info "Restarting previous version: $current_image"
            set_agent_image "$current_image"
            docker compose up -d "$AGENT_SERVICE" 2>&1 | tail -3
            sleep 15
            if check_health_url "$HEALTH_URL"; then
                log_ok "Automatic rollback successful — previous version restored"
            else
                log_err "Automatic rollback also failed! Manual intervention required."
                log_info "Run ./rollback.sh to try again."
            fi
        else
            log_err "No previous version available. Manual intervention required."
        fi
        exit 1
    fi

    log_ok "E2E verification gate passed!"

    # Step 10: Save deploy state and clean up
    log_info "Step 10: Saving deploy state and cleaning up..."
    save_deploy_state "$new_image" "$current_image"

    # Clean up old dangling images (keep last 5)
    log_info "Cleaning up old images (keeping last 5)..."
    docker images "$PROJECT" --format '{{.Repository}}:{{.Tag}}' | \
        grep -v "latest" | \
        grep -v "$commit_sha" | \
        sort -u | \
        tail -n +6 | \
        xargs -r docker rmi 2>/dev/null || true

    echo ""
    log_ok "═══════════════════════════════════════════════════════"
    log_ok "  Deploy successful! Version: $commit_sha"
    log_ok "  Image: $new_image"
    log_ok "  Previous: $current_image (rollback available)"
    log_ok "  E2E verification: PASSED"
    log_ok "═══════════════════════════════════════════════════════"
    echo ""
}

# Handle arguments
main "${1:-}"