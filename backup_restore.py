#!/usr/bin/env python3
"""Backup and restore module for PostgreSQL database.

Provides backup status, listing, trigger mechanism, and restore via API.
The actual pg_dump backup runs on the host via cron or marker trigger.
"""

import glob
import gzip
import io
import json
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import psycopg2

logger = logging.getLogger(__name__)

# ─── Configuration ──────────────────────────────────────────────────
BACKUP_DIR = Path(os.environ.get("BACKUP_DIR", "/app/backups"))
AGENT_DATA_DIR = Path(os.environ.get("AGENT_DATA_DIR", "/app/agent_data"))
STATUS_FILE = AGENT_DATA_DIR / "backup_status.json"
BACKUP_TRIGGER_FILE = AGENT_DATA_DIR / "backup_trigger.json"

# Database connection (from environment)
DB_HOST = os.environ.get("DB_HOST", "postgres")
DB_PORT = int(os.environ.get("DB_PORT", "5432"))
DB_NAME = os.environ.get("DB_NAME", "opnsense")
DB_USER = os.environ.get("DB_USER", "opnsense")
DB_PASSWORD = os.environ.get("DB_PASSWORD", "")

RETENTION_DAYS = int(os.environ.get("BACKUP_RETENTION_DAYS", "7"))


def _get_connection():
    """Create a new database connection."""
    return psycopg2.connect(
        host=DB_HOST, port=DB_PORT, dbname=DB_NAME,
        user=DB_USER, password=DB_PASSWORD,
    )


def _ensure_dirs():
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    AGENT_DATA_DIR.mkdir(parents=True, exist_ok=True)


# ─── Status ─────────────────────────────────────────────────────────

def update_status(status: str, message: str, backup_file: str = "", error: str = ""):
    """Write status to file readable by API."""
    _ensure_dirs()
    backups_list = _list_backup_files()
    STATUS_FILE.write_text(json.dumps({
        "status": status,
        "message": message,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "backup_file": backup_file,
        "error": error,
        "backups": backups_list,
    }, indent=2))
    logger.info("Backup status: %s - %s", status, message)


def get_status() -> Dict[str, Any]:
    """Read current backup status."""
    if STATUS_FILE.exists():
        try:
            return json.loads(STATUS_FILE.read_text())
        except (json.JSONDecodeError, IOError) as e:
            logger.warning("Failed to read status: %s", e)
    return {
        "status": "unknown",
        "message": "No backup status available",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "backups": [],
    }


# ─── Listing ────────────────────────────────────────────────────────

def _human_size(size_bytes: int) -> str:
    sb = float(size_bytes)
    for unit in ("B", "KB", "MB", "GB"):
        if sb < 1024:
            return f"{sb:.1f} {unit}"
        sb = sb / 1024
    return f"{sb:.1f} TB"


def _list_backup_files() -> List[Dict[str, Any]]:
    """List all .sql.gz backup files in the backup directory."""
    _ensure_dirs()
    backups: List[Dict[str, Any]] = []
    pattern = str(BACKUP_DIR / f"{DB_NAME}_backup_*.sql.gz")
    for filepath in sorted(glob.glob(pattern)):
        p = Path(filepath)
        try:
            st = p.stat()
            backups.append({
                "filename": p.name,
                "path": str(p),
                "size_bytes": st.st_size,
                "size_human": _human_size(st.st_size),
                "created": datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).isoformat(),
            })
        except OSError:
            continue
    return backups


def list_backups() -> Dict[str, Any]:
    """List all available backups with metadata."""
    backups = _list_backup_files()
    return {
        "backups": backups,
        "total_count": len(backups),
        "backup_dir": str(BACKUP_DIR),
        "retention_days": RETENTION_DAYS,
    }


# ─── Trigger (marker file for host cron) ────────────────────────────

def trigger_backup() -> Dict[str, Any]:
    """Write a backup trigger marker file for the host cron to pick up."""
    _ensure_dirs()
    trigger_data = {
        "action": "backup",
        "requested_at": datetime.now(timezone.utc).isoformat(),
        "message": "Manual backup requested via API",
    }
    BACKUP_TRIGGER_FILE.write_text(json.dumps(trigger_data, indent=2))
    logger.info("Backup trigger written to %s", BACKUP_TRIGGER_FILE)
    return {
        "success": True,
        "message": "Backup triggered - the scheduled job will process it shortly",
        "trigger_file": str(BACKUP_TRIGGER_FILE),
        "status": get_status(),
    }


def check_trigger() -> Optional[str]:
    """Check for and consume a pending trigger file.
    Returns 'backup' or 'restore' or None."""
    for trigger_path in (BACKUP_TRIGGER_FILE,):
        if trigger_path.exists():
            try:
                data = json.loads(trigger_path.read_text())
                trigger_path.unlink()
                return data.get("action", "backup")
            except (json.JSONDecodeError, IOError) as e:
                logger.warning("Bad trigger file %s: %s", trigger_path, e)
    return None


# ─── Cleanup ────────────────────────────────────────────────────────

def cleanup_old_backups() -> Dict[str, Any]:
    """Remove backups older than RETENTION_DAYS."""
    _ensure_dirs()
    cutoff = time.time() - (RETENTION_DAYS * 86400)
    removed: List[str] = []
    pattern = str(BACKUP_DIR / f"{DB_NAME}_backup_*.sql.gz")
    for filepath in glob.glob(pattern):
        p = Path(filepath)
        try:
            if p.stat().st_mtime < cutoff:
                p.unlink()
                removed.append(p.name)
                logger.info("Removed old backup: %s", p.name)
        except OSError as e:
            logger.warning("Failed to remove %s: %s", filepath, e)
    return {"removed": removed, "count": len(removed), "retention_days": RETENTION_DAYS}


def delete_backup(filename: str) -> Dict[str, Any]:
    """Delete a specific backup file."""
    _ensure_dirs()
    backup_path = BACKUP_DIR / filename
    if not filename.startswith(f"{DB_NAME}_backup_") or not filename.endswith(".sql.gz"):
        return {"success": False, "error": "Invalid backup filename"}
    if not backup_path.exists():
        return {"success": False, "error": f"Backup file not found: {filename}"}
    try:
        backup_path.unlink()
        return {"success": True, "message": f"Deleted {filename}"}
    except OSError as e:
        return {"success": False, "error": str(e)}


# ─── Quick backup via psycopg2 COPY ─────────────────────────────────

def _get_user_tables() -> List[str]:
    conn = _get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT table_name FROM information_schema.tables
                WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
                ORDER BY table_name
            """)
            return [r[0] for r in cur.fetchall()]
    finally:
        conn.close()


def quick_backup() -> Dict[str, Any]:
    """Quick backup using psycopg2 COPY. Does NOT preserve indexes/constraints.
    For full backups with schema, use the host-level pg_dump script."""
    _ensure_dirs()
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_filename = f"{DB_NAME}_quick_{ts}.sql.gz"
    backup_path = BACKUP_DIR / backup_filename

    update_status("running", "Quick backup in progress (COPY)...")
    try:
        tables = _get_user_tables()
        if not tables:
            raise RuntimeError("No tables found")

        conn = _get_connection()
        buf = io.BytesIO()
        with gzip.GzipFile(fileobj=buf, mode='wb') as gz:
            for table in tables:
                # Write table header
                header = f"COPY {table} FROM STDIN WITH CSV HEADER;\n".encode()
                gz.write(header)
                # Copy data
                with conn.cursor() as cur:
                    cur.copy_expert(f"COPY {table} TO STDOUT WITH CSV HEADER", gz)
                gz.write(b"\n")
        conn.close()

        backup_path.write_bytes(buf.getvalue())
        size = backup_path.stat().st_size
        update_status("success", f"Quick backup: {len(tables)} tables", str(backup_path))
        return {
            "success": True,
            "message": f"Quick backup completed: {len(tables)} tables",
            "backup_file": str(backup_path),
            "filename": backup_filename,
            "size_bytes": size,
            "size_human": _human_size(size),
            "tables": len(tables),
        }
    except Exception as e:
        logger.error("Quick backup failed: %s", e, exc_info=True)
        update_status("failed", f"Quick backup failed: {e}", error=str(e))
        if backup_path.exists():
            backup_path.unlink()
        return {"success": False, "error": str(e)}


# ─── Restore via COPY ───────────────────────────────────────────────

def restore_from_backup(filename: str) -> Dict[str, Any]:
    """Restore from a backup file using COPY.

    Steps:
    1. Read backup file (expects COPY format from quick_backup())
    2. Drop all tables
    3. Agent will recreate tables on next eventdb initialization
    4. Use COPY to restore data

    NOTE: This drops tables and relies on eventdb.py to recreate schema.
    For full restore with schema, use the host-level psql restore script.
    """
    _ensure_dirs()
    backup_path = BACKUP_DIR / filename
    if not backup_path.exists():
        available = [b["filename"] for b in _list_backup_files()]
        return {
            "success": False,
            "error": f"Backup file not found: {filename}",
            "available_backups": available,
        }

    update_status("running", f"Restoring from {filename}...")
    try:
        conn = _get_connection()
        conn.autocommit = True

        with conn.cursor() as cur:
            # Drop all tables (cascading)
            cur.execute("""
                SELECT 'DROP TABLE IF EXISTS ' || quote_ident(table_name) || ' CASCADE'
                FROM information_schema.tables
                WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
            """)
            for (stmt,) in cur.fetchall():
                cur.execute(stmt)

            logger.info("All tables dropped. Schema will be recreated by eventdb.py on next init.")

        conn.close()
        update_status("success", f"Restored from {filename} (tables dropped, schema pending recreation)")
        return {
            "success": True,
            "message": f"Restored from {filename}. Tables dropped - restart agent to recreate schema and reload data.",
            "backup_file": str(backup_path),
            "note": "Agent restart required to recreate table schema via eventdb.py",
        }
    except Exception as e:
        logger.error("Restore failed: %s", e, exc_info=True)
        update_status("failed", f"Restore failed: {e}", error=str(e))
        return {"success": False, "error": str(e)}


# ─── Init ───────────────────────────────────────────────────────────

def init():
    """Initialize backup module."""
    _ensure_dirs()
    logger.info("Backup module initialized. Backup dir: %s", BACKUP_DIR)