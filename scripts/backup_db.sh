#!/bin/bash
# backup_db.sh - PostgreSQL backup script for OPNsense Anomaly Agent
# Run from the host via cron or manually.
# Creates compressed pg_dump backups with 7-day retention.
# Sends Discord alert on failure.

set -euo pipefail

# ============================================================
# Configuration
# ============================================================
# Override via environment variables or .env file
# ============================================================
BACKUP_DIR="${BACKUP_DIR:-$HOME/opnsense-anomaly-agent/backups}"
POSTGRES_CONTAINER="${POSTGRES_CONTAINER:-anomaly-postgres}"
DB_NAME="${DB_NAME:-opnsense}"
DB_USER="${DB_USER:-opnsense}"
RETENTION_DAYS="${RETENTION_DAYS:-7}"
AGENT_DATA_DIR="${AGENT_DATA_DIR:-$HOME/opnsense-anomaly-agent/agent_data}"

# Discord webhook for alerts (set in .env or directly)
DISCORD_WEBHOOK_URL="${DISCORD_WEBHOOK_URL:-}"

# Timestamp for backup filename
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="${BACKUP_DIR}/${DB_NAME}_backup_${TIMESTAMP}.sql.gz"
STATUS_FILE="${AGENT_DATA_DIR}/backup_status.json"

# ============================================================
# Functions
# ============================================================

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

# Send Discord webhook alert
send_discord_alert() {
    local title="$1"
    local message="$2"
    local color="${3:-16711680}"  # Default red

    if [ -z "$DISCORD_WEBHOOK_URL" ]; then
        log "DISCORD_WEBHOOK_URL not set; skipping Discord alert"
        return 0
    fi

    curl -s -o /dev/null -w "%{http_code}" \
        -H "Content-Type: application/json" \
        -d "{
            \"embeds\": [{
                \"title\": \"\u{1f5c2} ${title}\",
                \"description\": \"${message}\",
                \"color\": ${color},
                \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"
            }]
        }" \
        "$DISCORD_WEBHOOK_URL" > /dev/null 2>&1 || true
}

# Update backup status file (readable by server.py)
update_status() {
    local status="$1"      # "running", "success", "failed"
    local message="$2"     # Human-readable status message
    local backup_file="$3" # Path to current backup file (if any)
    local error_msg="${4:-}"

    cat > "${STATUS_FILE}" <<EOF
{
    "status": "${status}",
    "message": "${message}",
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "backup_file": "${backup_file}",
    "error": "${error_msg}"
}
EOF
    log "Status updated: ${status} - ${message}"
}

# Clean up old backups beyond retention period
cleanup_old_backups() {
    log "Cleaning up backups older than ${RETENTION_DAYS} days..."
    local count
    count=$(find "${BACKUP_DIR}" -name "${DB_NAME}_backup_*.sql.gz" -mtime +${RETENTION_DAYS} 2>/dev/null | wc -l | tr -d ' ')

    if [ "$count" -gt 0 ]; then
        find "${BACKUP_DIR}" -name "${DB_NAME}_backup_*.sql.gz" -mtime +${RETENTION_DAYS} -delete
        log "Removed ${count} old backup(s)"
    else
        log "No old backups to remove"
    fi
}

# Get list of current backups for status reporting
list_backups() {
    echo "["
    local first=true
    for f in "${BACKUP_DIR}"/${DB_NAME}_backup_*.sql.gz; do
        [ -f "$f" ] || continue
        local fname
        fname=$(basename "$f")
        local fsize
        fsize=$(stat -f%z "$f" 2>/dev/null || stat -c%s "$f" 2>/dev/null || echo "0")
        local fdate
        fdate=$(stat -f%Sm "$f" 2>/dev/null || stat -c%y "$f" 2>/dev/null | cut -d' ' -f1-2 || echo "unknown")
        if [ "$first" = true ]; then
            first=false
        else
            echo ","
        fi
        printf '  {"filename": "%s", "size_bytes": %s, "date": "%s"}' "$fname" "$fsize" "$fdate"
    done
    echo ""
    echo "]"
}

# ============================================================
# Main: Perform backup
# ============================================================

main() {
    # Ensure backup directory exists
    mkdir -p "${BACKUP_DIR}"
    mkdir -p "${AGENT_DATA_DIR}"

    log "Starting backup of ${DB_NAME}..."
    update_status "running" "Backup in progress..." ""

    # Check that postgres container is running
    if ! docker ps --format '{{.Names}}' | grep -q "^${POSTGRES_CONTAINER}$"; then
        local error="PostgreSQL container '${POSTGRES_CONTAINER}' is not running"
        log "ERROR: ${error}"
        update_status "failed" "Backup failed" "" "$error"
        send_discord_alert "Backup Failed" "PostgreSQL container is not running" 16711680
        return 1
    fi

    # Run pg_dump inside the postgres container, compress with gzip
    log "Running pg_dump via docker exec..."
    local pg_dump_exit_code=0
    local pg_dump_output

    pg_dump_output=$(docker exec "${POSTGRES_CONTAINER}" \
        pg_dump -U "${DB_USER}" -d "${DB_NAME}" --clean --if-exists 2>&1) || pg_dump_exit_code=$?

    if [ "$pg_dump_exit_code" -ne 0 ]; then
        local error="pg_dump failed (exit code ${pg_dump_exit_code}): $(echo "$pg_dump_output" | tail -5)"
        log "ERROR: ${error}"
        update_status "failed" "Backup failed" "" "$error"
        send_discord_alert "Backup Failed" "pg_dump exit code ${pg_dump_exit_code}" 16711680
        return 1
    fi

    # Compress and write to file
    log "Compressing backup to ${BACKUP_FILE}..."
    echo "$pg_dump_output" | gzip > "${BACKUP_FILE}" || {
        local error="Failed to compress backup file"
        log "ERROR: ${error}"
        update_status "failed" "Backup failed" "" "$error"
        send_discord_alert "Backup Failed" "Compression failed" 16711680
        return 1
    }

    # Verify the backup file exists and is non-empty
    local backup_size
    backup_size=$(stat -f%z "${BACKUP_FILE}" 2>/dev/null || stat -c%s "${BACKUP_FILE}" 2>/dev/null || echo "0")

    if [ "$backup_size" -eq 0 ]; then
        local error="Backup file is empty"
        log "ERROR: ${error}"
        update_status "failed" "Backup failed" "" "$error"
        send_discord_alert "Backup Failed" "Backup file is empty" 16711680
        rm -f "${BACKUP_FILE}"
        return 1
    fi

    log "Backup completed: ${BACKUP_FILE} (${backup_size} bytes)"

    # Clean up old backups
    cleanup_old_backups

    # Update status
    update_status "success" "Backup completed successfully" "${BACKUP_FILE}"

    # Send success notification to Discord (optional - only on schedule)
    if [ "${DISCORD_ALERT_SUCCESS:-false}" = "true" ]; then
        send_discord_alert "Backup Successful" "Backup: ${BACKUP_FILE} (${backup_size} bytes)" 65280
    fi

    # Also update the backup list in the status file
    local backup_list
    backup_list=$(list_backups)
    cat > "${STATUS_FILE}" <<EOF
{
    "status": "success",
    "message": "Backup completed successfully",
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "backup_file": "${BACKUP_FILE}",
    "backups": ${backup_list}
}
EOF

    log "All done."
    return 0
}

# ============================================================
# Restore: Restore from a backup file
# ============================================================

do_restore() {
    local restore_file="$1"

    if [ -z "$restore_file" ]; then
        echo "Usage: $0 restore <backup_file>"
        echo "Available backups:"
        ls -lh "${BACKUP_DIR}"/${DB_NAME}_backup_*.sql.gz 2>/dev/null || echo "  (none)"
        return 1
    fi

    # Resolve relative paths
    if [[ "$restore_file" != /* ]]; then
        restore_file="${BACKUP_DIR}/${restore_file}"
    fi

    if [ ! -f "$restore_file" ]; then
        log "ERROR: Backup file not found: ${restore_file}"
        return 1
    fi

    log "Restoring from: ${restore_file}"
    update_status "running" "Restore in progress from $(basename "$restore_file")" "$restore_file"

    # Check postgres container
    if ! docker ps --format '{{.Names}}' | grep -q "^${POSTGRES_CONTAINER}$"; then
        local error="PostgreSQL container '${POSTGRES_CONTAINER}' is not running"
        log "ERROR: ${error}"
        update_status "failed" "Restore failed" "$restore_file" "$error"
        return 1
    fi

    # Stop the agent to prevent writes during restore
    local agent_container="anomaly-agent"
    local agent_was_running=false
    if docker ps --format '{{.Names}}' | grep -q "^${agent_container}$"; then
        agent_was_running=true
        log "Stopping agent container during restore..."
        docker stop "$agent_container" 2>/dev/null || true
        sleep 2
    fi

    # Restore the database
    log "Restoring database..."
    local restore_exit_code=0
    local restore_output

    restore_output=$(gunzip -c "$restore_file" | docker exec -i "${POSTGRES_CONTAINER}" \
        psql -U "${DB_USER}" -d "${DB_NAME}" 2>&1) || restore_exit_code=$?

    # Restart agent if it was running
    if [ "$agent_was_running" = true ]; then
        log "Restarting agent container..."
        docker start "$agent_container" 2>/dev/null || true
    fi

    if [ "$restore_exit_code" -ne 0 ]; then
        local error="Restore failed (exit code ${restore_exit_code}): $(echo "$restore_output" | tail -5)"
        log "ERROR: ${error}"
        update_status "failed" "Restore failed" "$restore_file" "$error"
        send_discord_alert "Restore Failed" "Restore from $(basename "$restore_file") failed" 16711680
        return 1
    fi

    log "Restore completed successfully from $(basename "$restore_file")"
    update_status "success" "Restore completed from $(basename "$restore_file")" "$restore_file"
    send_discord_alert "Restore Successful" "Restored from $(basename "$restore_file")" 65280
    return 0
}

# ============================================================
# Entry point
# ============================================================

# Check for API trigger file first
check_trigger() {
    local trigger_file="${AGENT_DATA_DIR}/backup_trigger.json"
    if [ -f "$trigger_file" ]; then
        local requester
        requester=$(cat "$trigger_file" 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('requested_at','unknown'))" 2>/dev/null || echo "unknown")
        log "API backup trigger detected (requested at: ${requester})"
        rm -f "$trigger_file"
        main
        return $?
    fi
    return 1
}

case "${1:-backup}" in
    backup)
        main
        ;;
    restore)
        do_restore "$2"
        ;;
    list)
        list_backups
        ;;
    status)
        if [ -f "${STATUS_FILE}" ]; then
            cat "${STATUS_FILE}"
        else
            echo '{"status": "unknown", "message": "No backup status available"}'
        fi
        ;;
    check-trigger)
        check_trigger
        ;;
    *)
        echo "Usage: $0 {backup|restore <file>|list|status|check-trigger}"
        exit 1
        ;;
esac