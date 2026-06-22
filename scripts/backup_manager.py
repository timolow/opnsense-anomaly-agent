#!/usr/bin/env python3
"""
PostgreSQL Backup/Restore Manager for OPNsense Anomaly Agent.

Handles automated pg_dump backups with gzip compression,
retention policy (keep last N days), restore capability,
and Discord notifications on failure.

Usage as standalone script:
    python scripts/backup_manager.py backup      # manual backup
    python scripts/backup_manager.py restore FILE # restore from specific file
    python scripts/backup_manager.py list         # list available backups
    python scripts/backup_manager.py cleanup      # enforce retention policy

Usage as module:
    from scripts.backup_manager import BackupManager
    mgr = BackupManager()
    result = mgr.create_backup()
"""

import gzip
import json
import logging
import os
import shutil
import subprocess
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)

# Configuration from environment
BACKUP_DIR = Path(os.environ.get("BACKUP_DIR", "/app/backups"))
BACKUP_RETENTION_DAYS = int(os.environ.get("BACKUP_RETENTION_DAYS", "7"))
BACKUP_COMPRESSION = os.environ.get("BACKUP_COMPRESSION", "gzip")  # gzip or none
PG_CONTAINER = os.environ.get("PG_CONTAINER", "anomaly-postgres")
PG_USER = os.environ.get("DB_USER", "opnsense")
PG_DB = os.environ.get("DB_NAME", "opnsense")
PG_HOST = os.environ.get("DB_HOST", "postgres")
PG_PORT = os.environ.get("DB_PORT", "5432")
PG_PASSWORD = os.environ.get("DB_PASSWORD", "")
DISCORD_WEBHOOK_URL = os.environ.get("DISCORD_WEBHOOK_URL", "")
BACKUP_ON_STARTUP = os.environ.get("BACKUP_ON_STARTUP", "false").lower() == "true"


class BackupManager:
    """Manages PostgreSQL backups and restores."""

    def __init__(self, backup_dir: Optional[Path] = None, retention_days: Optional[int] = None):
        self.backup_dir = backup_dir or BACKUP_DIR
        self.retention_days = retention_days or BACKUP_RETENTION_DAYS
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        self._last_backup_status: Dict[str, Any] = {}

    def _generate_backup_filename(self) -> str:
        """Generate a timestamped backup filename."""
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        return f"backup_{ts}.sql.gz"

    def _get_pg_dump_connstr(self) -> str:
        """Build connection string for pg_dump inside container."""
        # Inside container, connect to postgres service directly
        parts = []
        parts.append(f"host={PG_HOST}")
        parts.append(f"port={PG_PORT}")
        parts.append(f"user={PG_USER}")
        parts.append(f"dbname={PG_DB}")
        if PG_PASSWORD:
            os.environ["PGPASSWORD"] = PG_PASSWORD
        return " ".join(parts)

    def create_backup(self, force: bool = False) -> Dict[str, Any]:
        """
        Create a compressed backup of the PostgreSQL database.

        Returns a dict with backup metadata and status.
        """
        result: Dict[str, Any] = {
            "status": "pending",
            "filename": "",
            "size_bytes": 0,
            "size_human": "",
            "duration_sec": 0.0,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "error": None,
        }

        try:
            filename = self._generate_backup_filename()
            filepath = self.backup_dir / filename
            result["filename"] = filename

            # Check if a backup already exists from the last minute (avoid duplicates)
            if not force:
                existing = list(self.backup_dir.glob("backup_*.sql.gz"))
                recent = [f for f in existing if (datetime.now(timezone.utc) - self._file_mtime(f)).total_seconds() < 60]
                if recent:
                    logger.warning(f"Backup already created in last 60s: {recent[0].name}. Skipping.")
                    result["status"] = "skipped"
                    result["filename"] = recent[0].name
                    result["size_bytes"] = recent[0].stat().st_size
                    result["size_human"] = self._human_size(recent[0].stat().st_size)
                    self._last_backup_status = result
                    return result

            # Run pg_dump inside the container, pipe through gzip
            start_time = time.time()

            # Build the pg_dump command
            # We run docker exec to get pg_dump, pipe to gzip on host
            cmd = [
                "docker", "exec", "-i", PG_CONTAINER,
                "pg_dump",
                "-U", PG_USER,
                "-d", PG_DB,
                "--no-owner",
                "--no-privileges",
                "--clean",
                "--if-exists",
                "--create",
            ]

            if PG_PASSWORD:
                env = os.environ.copy()
                env["PGPASSWORD"] = PG_PASSWORD
            else:
                env = None

            logger.info(f"Starting backup: {filename}")

            # Stream pg_dump output to gzip file
            # Write to temp file first, then gzip (subprocess needs file descriptor for stdout)
            tmp_path = filepath.with_suffix(".sql")
            with open(tmp_path, "wb") as sql_file:
                proc = subprocess.run(
                    cmd,
                    stdout=sql_file,
                    stderr=subprocess.PIPE,
                    env=env,
                    timeout=300,
                )

                if proc.returncode != 0:
                    tmp_path.unlink(missing_ok=True)
                    raise RuntimeError(f"pg_dump failed (exit {proc.returncode}): {proc.stderr.decode(errors='replace')[:500]}")

            # Compress the SQL dump
            with open(tmp_path, "rb") as f_in:
                with gzip.open(filepath, "wb", compresslevel=6) as f_out:
                    shutil.copyfileobj(f_in, f_out)
            tmp_path.unlink(missing_ok=True)

            duration = time.time() - start_time
            file_size = filepath.stat().st_size

            result["status"] = "success"
            result["duration_sec"] = round(duration, 2)
            result["size_bytes"] = file_size
            result["size_human"] = self._human_size(file_size)

            logger.info(f"Backup complete: {filename} ({self._human_size(file_size)}, {duration:.1f}s)")

            # Send Discord notification on success
            self._notify_discord("backup_success", result)

            self._last_backup_status = result
            return result

        except subprocess.TimeoutExpired:
            result["status"] = "error"
            result["error"] = "Backup timed out after 300 seconds"
            logger.error(result["error"])
            self._notify_discord("backup_failure", result)
            self._last_backup_status = result
            return result
        except FileNotFoundError:
            result["status"] = "error"
            result["error"] = f"Docker container '{PG_CONTAINER}' not found. Is it running?"
            logger.error(result["error"])
            self._notify_discord("backup_failure", result)
            self._last_backup_status = result
            return result
        except Exception as e:
            result["status"] = "error"
            result["error"] = str(e)
            logger.error(f"Backup failed: {e}")
            self._notify_discord("backup_failure", result)
            self._last_backup_status = result
            return result

    def list_backups(self) -> List[Dict[str, Any]]:
        """List all available backup files with metadata."""
        backups = []
        pattern = "backup_*.sql.gz"

        for f in sorted(self.backup_dir.glob(pattern), reverse=True):
            stat = f.stat()
            mtime = self._file_mtime(f)
            backups.append({
                "filename": f.name,
                "path": str(f),
                "size_bytes": stat.st_size,
                "size_human": self._human_size(stat.st_size),
                "created_at": mtime.isoformat(),
                "age_days": round((datetime.now(timezone.utc) - mtime).total_seconds() / 86400, 1),
            })

        return backups

    def restore_backup(self, filename: str) -> Dict[str, Any]:
        """
        Restore the database from a specific backup file.

        WARNING: This drops and recreates the database. All current data is lost.

        Returns a dict with restore status.
        """
        filepath = self.backup_dir / filename

        result: Dict[str, Any] = {
            "status": "pending",
            "filename": filename,
            "duration_sec": 0.0,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "error": None,
        }

        if not filepath.exists():
            result["status"] = "error"
            result["error"] = f"Backup file not found: {filename}"
            logger.error(result["error"])
            self._notify_discord("restore_failure", result)
            return result

        try:
            start_time = time.time()
            logger.info(f"Starting restore from: {filename}")

            # Drop and recreate the database, then restore
            # pg_restore with --clean --create handles this
            env = os.environ.copy()
            if PG_PASSWORD:
                env["PGPASSWORD"] = PG_PASSWORD

            # Gunzip and pipe to psql inside container
            # First, get the superuser to drop/create the db
            # We need to restore as superuser or the db owner
            # Using pg_restore-style: gunzip | docker exec psql

            # Step 1: Drop the database (as superuser)
            drop_cmd = [
                "docker", "exec", "-i", PG_CONTAINER,
                "psql", "-U", "postgres", "-d", "postgres",
                "-c", f"DROP DATABASE IF EXISTS {PG_DB};",
            ]
            proc = subprocess.run(drop_cmd, capture_output=True, timeout=30, env=env)
            if proc.returncode != 0:
                # Try to continue anyway - db might already be gone
                logger.warning(f"Drop database warning: {proc.stderr.decode(errors='replace')[:200]}")

            # Step 2: Recreate the database
            create_cmd = [
                "docker", "exec", "-i", PG_CONTAINER,
                "psql", "-U", "postgres", "-d", "postgres",
                "-c", f"CREATE DATABASE {PG_DB} OWNER {PG_USER};",
            ]
            proc = subprocess.run(create_cmd, capture_output=True, timeout=30, env=env)
            if proc.returncode != 0:
                raise RuntimeError(f"Create database failed: {proc.stderr.decode(errors='replace')[:500]}")

            # Step 3: Restore the data
            restore_cmd = [
                "docker", "exec", "-i", PG_CONTAINER,
                "psql", "-U", PG_USER, "-d", PG_DB,
            ]

            with gzip.open(filepath, "rb") as gz_file:
                proc = subprocess.run(
                    restore_cmd,
                    input=gz_file.read(),
                    capture_output=True,
                    timeout=300,
                    env=env,
                )

            if proc.returncode != 0:
                stderr = proc.stderr.decode(errors="replace")[:1000]
                # Some SQL warnings are OK (e.g., "CREATE TABLE /relation already exists" from --clean)
                # But actual errors are not
                raise RuntimeError(f"psql restore returned {proc.returncode}: {stderr}")

            duration = time.time() - start_time
            result["status"] = "success"
            result["duration_sec"] = round(duration, 2)

            logger.info(f"Restore complete: {filename} ({duration:.1f}s)")
            self._notify_discord("restore_success", result)
            return result

        except subprocess.TimeoutExpired:
            result["status"] = "error"
            result["error"] = "Restore timed out after 300 seconds"
            logger.error(result["error"])
            self._notify_discord("restore_failure", result)
            return result
        except Exception as e:
            result["status"] = "error"
            result["error"] = str(e)
            logger.error(f"Restore failed: {e}")
            self._notify_discord("restore_failure", result)
            return result

    def enforce_retention(self) -> Dict[str, Any]:
        """
        Delete backups older than retention period. Returns cleanup stats."""
        cutoff = datetime.now(timezone.utc) - timedelta(days=self.retention_days)
        deleted = []
        kept = []

        for f in self.backup_dir.glob("backup_*.sql.gz"):
            mtime = self._file_mtime(f)
            if mtime < cutoff:
                try:
                    f.unlink()
                    deleted.append(f.name)
                    logger.info(f"Deleted old backup: {f.name} (age: {(datetime.now(timezone.utc) - mtime).days}d)")
                except OSError as e:
                    logger.error(f"Failed to delete {f.name}: {e}")
            else:
                kept.append(f.name)

        result = {
            "deleted_count": len(deleted),
            "kept_count": len(kept),
            "deleted_files": deleted,
            "retention_days": self.retention_days,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        if deleted:
            logger.info(f"Retention cleanup: deleted {len(deleted)}, kept {len(kept)}")

        return result

    def get_status(self) -> Dict[str, Any]:
        """Get comprehensive backup status for dashboard."""
        backups = self.list_backups()
        retention = self.enforce_retention()

        last_backup = backups[0] if backups else None

        return {
            "backup_dir": str(self.backup_dir),
            "retention_days": self.retention_days,
            "total_backups": len(backups),
            "latest_backup": last_backup,
            "backups": backups[:10],  # Last 10
            "last_cleanup": {
                "deleted_count": retention["deleted_count"],
                "timestamp": retention["timestamp"],
            },
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    def _file_mtime(self, path: Path) -> datetime:
        """Get file modification time as timezone-aware datetime."""
        mtime_ts = path.stat().st_mtime
        return datetime.fromtimestamp(mtime_ts, tz=timezone.utc)

    @staticmethod
    def _human_size(size_bytes: int) -> str:
        """Convert bytes to human-readable size."""
        for unit in ["B", "KB", "MB", "GB"]:
            if size_bytes < 1024:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024
        return f"{size_bytes:.1f} TB"

    def _notify_discord(self, event_type: str, result: Dict[str, Any]):
        """Send Discord notification for backup events."""
        if not DISCORD_WEBHOOK_URL:
            return

        color_map = {
            "backup_success": 0x00ff00,    # Green
            "backup_failure": 0xff0000,    # Red
            "restore_success": 0x00bfff,   # Blue
            "restore_failure": 0xff4500,   # Orange
        }

        title_map = {
            "backup_success": ":white_check_mark: Backup Successful",
            "backup_failure": ":x: Backup FAILED",
            "restore_success": ":arrow_double_down: Restore Successful",
            "restore_failure": ":x: Restore FAILED",
        }

        color = color_map.get(event_type, 0xffffff)
        title = title_map.get(event_type, event_type)

        fields = []
        if result.get("filename"):
            fields.append({"name": "File", "value": result["filename"], "inline": True})
        if result.get("size_human"):
            fields.append({"name": "Size", "value": result["size_human"], "inline": True})
        if result.get("duration_sec"):
            fields.append({"name": "Duration", "value": f"{result['duration_sec']:.1f}s", "inline": True})
        if result.get("error"):
            fields.append({"name": "Error", "value": f"```{result['error'][:500]}```", "inline": False})

        embed = {
            "title": title,
            "color": color,
            "fields": fields,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "footer": {"text": "OPNsense Anomaly Agent"},
        }

        payload = {
            "embeds": [embed],
            "username": "Backup Bot",
        }

        try:
            import urllib.request
            req = urllib.request.Request(
                DISCORD_WEBHOOK_URL,
                data=json.dumps(payload).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                logger.info(f"Discord notification sent: {event_type} ({resp.status})")
        except Exception as e:
            logger.warning(f"Failed to send Discord notification: {e}")


# --- Standalone CLI ---

def main():
    """CLI entry point for backup operations."""
    import argparse

    parser = argparse.ArgumentParser(description="PostgreSQL Backup Manager")
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # backup
    backup_parser = subparsers.add_parser("backup", help="Create a new backup")
    backup_parser.add_argument("--force", action="store_true", help="Force backup even if recent one exists")

    # restore
    restore_parser = subparsers.add_parser("restore", help="Restore from a backup")
    restore_parser.add_argument("filename", help="Backup filename to restore from")

    # list
    subparsers.add_parser("list", help="List available backups")

    # cleanup
    subparsers.add_parser("cleanup", help="Enforce retention policy")

    # status
    subparsers.add_parser("status", help="Show backup status")

    args = parser.parse_args()

    mgr = BackupManager()

    if args.command == "backup":
        result = mgr.create_backup(force=args.force)
    elif args.command == "restore":
        print(f"WARNING: This will DROP and recreate the database '{PG_DB}'. All current data will be lost.")
        confirm = input(f"Type '{args.filename}' to confirm restore: ")
        if confirm != args.filename:
            print("Restore cancelled.")
            return
        result = mgr.restore_backup(args.filename)
    elif args.command == "list":
        backups = mgr.list_backups()
        if not backups:
            print("No backups found.")
            return
        for b in backups:
            print(f"  {b['filename']}  {b['size_human']:>10}  {b['created_at']}  (age: {b['age_days']}d)")
        return
    elif args.command == "cleanup":
        result = mgr.enforce_retention()
    elif args.command == "status":
        result = mgr.get_status()
    else:
        parser.print_help()
        return

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()