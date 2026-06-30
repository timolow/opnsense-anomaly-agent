#!/usr/bin/env python3
"""Syslog listener for OPNsense firewall logs.
Runs on the Mac host to receive UDP syslog, writes to shared JSONL file.
The Docker agent reads events from this file.

When used via SyslogListener with a callback (SYSLOG_ENABLED=true in Docker),
all JSONL file I/O is skipped — events go directly to the callback.

Log rotation:
  - Daily rotation at midnight UTC for both syslog_events.jsonl and syslog_listener.log
  - 7-day retention (older files compressed with gzip and deleted)
  - Max 100MB per JSONL file (size-based safety rotation)
"""

from __future__ import annotations

import gzip
import glob
import os
import json
import socket
import threading
import logging
import shutil
import re
from datetime import datetime, timezone
from pathlib import Path

# Redis Stream configuration (overridable via environment variables)
REDIS_STREAM_ENABLED = os.getenv("REDIS_STREAM_ENABLED", "false").lower() in ("true", "1", "yes")
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")
REDIS_STREAM_NAME = os.getenv("REDIS_STREAM_NAME", "event_ingest")

# Configuration (overridable via environment variables)
UDP_PORT = int(os.getenv("SYSLOG_UDP_PORT", "1514"))
DATA_DIR = os.getenv("DATA_DIR", str(Path(__file__).parent / "agent_data"))
OUTPUT_FILE = os.getenv("JSONL_PATH", os.path.join(DATA_DIR, "syslog_events.jsonl"))
LOG_FILE = os.path.join(DATA_DIR, "syslog_listener.log")
EVENT_COUNT_FILE = os.path.join(DATA_DIR, "syslog_event_count.txt")

# Rotation settings
JSONL_MAX_BYTES = int(os.getenv("JSONL_MAX_BYTES", "100000000"))  # 100MB
JSONL_RETENTION_DAYS = int(os.getenv("JSONL_RETENTION_DAYS", "7"))


class RotatingJSONLWriter:
    """Thread-safe JSONL writer with daily rotation and gzip compression.

    Rotation policy:
      - Rotates at midnight UTC daily
      - Keeps JSONL_RETENTION_DAYS days of rotated logs
      - Compresses rotated logs with gzip (.gz suffix)
      - Enforces JSONL_MAX_BYTES limit to prevent runaway growth
    """

    def __init__(self, base_path: str, max_bytes: int = JSONL_MAX_BYTES, backup_count: int = JSONL_RETENTION_DAYS):
        self.base_path = base_path
        self.max_bytes = max_bytes
        self.backup_count = backup_count
        self._lock = threading.Lock()
        self._current_date = self._today_utc()
        self._file = None
        self._file_date = None
        self._size = 0
        # Initialize file
        self._open_file()

    def _today_utc(self) -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%d")

    def _open_file(self):
        """Open the current JSONL file for appending."""
        if self._file and self._file_date == self._current_date:
            return  # Already open for today
        # Close existing file
        if self._file:
            try:
                self._file.close()
            except OSError:
                pass
        # Open new file
        data_dir = os.path.dirname(self.base_path)
        if data_dir:
            os.makedirs(data_dir, exist_ok=True)
        self._file = open(self.base_path, "a", encoding="utf-8")
        self._file_date = self._current_date
        self._size = os.path.getsize(self.base_path) if os.path.exists(self.base_path) else 0

    def _rotate(self):
        """Rotate the current file: rename, compress, cleanup old files."""
        if not self._file:
            return
        self._file.close()
        self._file = None

        today = self._today_utc()
        rotated_name = self.base_path + "." + today
        gz_name = rotated_name + ".gz"

        # Check if today's rotated file already exists (same-day size rotation)
        if os.path.exists(rotated_name) or os.path.exists(gz_name):
            # Same-day rotation: find next available counter suffix
            counter = 1
            while os.path.exists(f"{rotated_name}.{counter}") or os.path.exists(f"{rotated_name}.{counter}.gz"):
                counter += 1
            rotated_name = f"{rotated_name}.{counter}"

        # Rename current file to date-stamped name
        if os.path.exists(self.base_path):
            try:
                os.rename(self.base_path, rotated_name)
                # Compress the rotated file
                self._compress_file(rotated_name)
            except OSError:
                # If rename fails (e.g., race condition), just reopen
                pass

        # Clean up old rotated files beyond backupCount
        self._cleanup_old_files()

        # Reset size counter
        self._size = 0

    def _compress_file(self, filepath: str):
        """Compress a file with gzip, removing the original on success."""
        gz_path = filepath + ".gz"
        if os.path.exists(gz_path):
            return  # Already compressed
        try:
            with open(filepath, "rb") as f_in:
                with gzip.open(gz_path, "wb", compresslevel=6) as f_out:
                    shutil.copyfileobj(f_in, f_out)
            os.remove(filepath)
        except OSError:
            pass

    def _cleanup_old_files(self):
        """Remove rotated JSONL files older than backup_count days."""
        pattern_gz = self.base_path + ".*.gz"
        pattern_plain = self.base_path + ".*"
        rotated_files = []

        for f in glob.glob(pattern_gz):
            rotated_files.append(f)
        for f in glob.glob(pattern_plain):
            if not f.endswith(".gz") and f != self.base_path:
                rotated_files.append(f)

        # Sort by modification time, newest first
        rotated_files.sort(key=os.path.getmtime, reverse=True)

        # Remove files beyond backup_count
        for old_file in rotated_files[self.backup_count:]:
            try:
                os.remove(old_file)
            except OSError:
                pass

    def write(self, line: str):
        """Write a single JSONL line with rotation check."""
        with self._lock:
            today = self._today_utc()
            if today != self._current_date:
                self._current_date = today
                self._rotate()
                self._open_file()

            encoded = line.encode("utf-8") if isinstance(line, str) else line
            # Size-based rotation check
            if self.max_bytes > 0 and (self._size + len(encoded)) >= self.max_bytes:
                self._rotate()
                self._open_file()

            if self._file:
                self._file.write(line if isinstance(line, str) else line.decode("utf-8"))
                self._file.flush()
                self._size += len(encoded)

    def close(self):
        """Close the writer and release resources."""
        with self._lock:
            if self._file:
                try:
                    self._file.close()
                except OSError:
                    pass
                self._file = None


# Lazy Redis Stream client (only initialized when REDIS_STREAM_ENABLED)
_redis_client = None
_redis_available = False


def _get_redis_client():
    """Return a Redis client, initializing lazily. Returns None if unavailable."""
    global _redis_client, _redis_available
    if _redis_available and _redis_client is not None:
        return _redis_client

    if not REDIS_STREAM_ENABLED:
        return None

    try:
        import redis
        _redis_client = redis.from_url(REDIS_URL, socket_timeout=3, decode_responses=True)
        _redis_client.ping()
        _redis_available = True
        logger().info("Redis Stream client connected (%s, stream=%s)", REDIS_URL, REDIS_STREAM_NAME)
        return _redis_client
    except Exception as e:
        logger().warning("Redis Stream unavailable (will fall back to callback): %s", e)
        _redis_available = False
        _redis_client = None
        return None


def push_to_redis_stream(event: dict) -> bool:
    """Push a parsed event to the Redis Stream. Returns True on success."""
    global _redis_available, _redis_client
    client = _get_redis_client()
    if client is None:
        return False
    try:
        # XADD with auto-generated ID (*), field 'event' -> JSON payload
        client.xadd(REDIS_STREAM_NAME, {"event": json.dumps(event)}, id="*")
        return True
    except Exception as e:
        logger().warning("Redis XADD failed (falling back to callback): %s", e)
        _redis_available = False
        _redis_client = None
        return False
_jsonl_writer: RotatingJSONLWriter | None = None


def _get_jsonl_writer() -> RotatingJSONLWriter:
    """Return the JSONL writer, initializing on first call."""
    global _jsonl_writer
    if _jsonl_writer is None:
        _jsonl_writer = RotatingJSONLWriter(
            OUTPUT_FILE,
            max_bytes=JSONL_MAX_BYTES,
            backup_count=JSONL_RETENTION_DAYS,
        )
    return _jsonl_writer


# Lazy logger setup — deferred until actually needed (not at import time).
# When SyslogListener is used with a callback, logging to LOG_FILE is still
# desirable for diagnostics, but JSONL/event-counter writes are fully skipped.
_logger: logging.Logger | None = None


def _get_logger() -> logging.Logger:
    """Return the module logger, initializing on first call."""
    global _logger
    if _logger is None:
        from json_logging import setup_json_logging
        setup_json_logging(
            level=logging.INFO,
            log_file=LOG_FILE,
            stdout=False,
        )
        _logger = logging.getLogger(__name__)
    return _logger


def logger():
    """Module-level logger property."""
    return _get_logger()


# Ensure output directory exists (lazy — deferred until first file write)
def _ensure_output_dir():
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)

# Initialize event counter (lazy — only when file writes are needed)
def _init_event_counter():
    if not os.path.exists(EVENT_COUNT_FILE):
        with open(EVENT_COUNT_FILE, 'w') as f:
            f.write('0')

def get_event_count():
    try:
        with open(EVENT_COUNT_FILE, 'r') as f:
            return int(f.read().strip())
    except Exception:
        return 0

def set_event_count(count):
    with open(EVENT_COUNT_FILE, 'w') as f:
        f.write(str(count))

# Adaptive parser — lazy init to avoid overhead when callback mode is active
_parser = None


def _get_parser():
    """Return the adaptive parser, initializing on first call."""
    global _parser
    if _parser is None:
        from adaptive_parser import AdaptiveParser
        _parser = AdaptiveParser()
    return _parser

def _convert_timestamp(raw_ts):
    """Convert raw syslog timestamp to ISO format for PostgreSQL.
    
    Syslog format: 'Jun 14 14:06:24'
    PostgreSQL format: '2026-06-14T14:06:24'
    """
    if not raw_ts or 'T' in raw_ts:
        return raw_ts
    try:
        dt = datetime.strptime(raw_ts, "%b %d %H:%M:%S")
        return dt.replace(year=datetime.now().year).isoformat()
    except Exception:
        return raw_ts


def parse_syslog_line(line):
    """Parse any log line using the adaptive parser."""
    try:
        event = _get_parser().parse_line(line.strip())
        if event:
            # Convert raw syslog timestamp to ISO format for PostgreSQL
            event['timestamp'] = _convert_timestamp(event.get('timestamp', ''))
            event['_received_at'] = datetime.now().isoformat()
        return event
    except Exception as e:
        logger().warning("Error parsing syslog line: %s", e)
        return None

def write_event(event, write_to_file=True):
    """Append event to JSONL file with rotation.

    Args:
        event: parsed event dict
        write_to_file: if False, skip file I/O entirely (callback mode)
    """
    if not write_to_file:
        return True
    try:
        _get_jsonl_writer().write(json.dumps(event) + "\n")
        return True
    except Exception as e:
        logger().error(f"Error writing event: {e}")
        return False

def run_syslog_listener(event_callback=None):
    """Run the syslog UDP listener.

    Binds to 0.0.0.0 (all interfaces) because OPNsense sends syslog from
    any network interface. This is safe — UDP syslog is firewalled and
    only trusted OPNsense hosts are configured to send to this port.
    The bind address can be overridden with SYSLOG_BIND env var.

    Args:
        event_callback: callable(event_dict) -> None. If provided, events
                       go directly to the callback and ALL JSONL file I/O
                       (writing, rotation, event counter) is skipped entirely.
                       If None, falls back to legacy JSONL file mode.
    """
    bind_host = os.getenv("SYSLOG_BIND", "0.0.0.0")
    callback_mode = event_callback is not None

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        if not callback_mode:
            _ensure_output_dir()
            _init_event_counter()
        sock.bind((bind_host, UDP_PORT))
        if callback_mode:
            logger().info("Syslog listener started on UDP port %d (callback mode, no file I/O)", UDP_PORT)
        else:
            logger().info("Syslog listener started on UDP port %d", UDP_PORT)
            logger().info("Events will be written to: %s", OUTPUT_FILE)

        count = 0
        while True:
            try:
                data, addr = sock.recvfrom(65535)
                line = data.decode('utf-8', errors='replace').strip()

                if not line:
                    continue

                logger().debug(f"Received from {addr}: {line[:100]}...")

                event = parse_syslog_line(line)
                if event:
                    count += 1
                    if callback_mode:
                        # Try Redis Stream first, fall back to callback
                        if REDIS_STREAM_ENABLED and push_to_redis_stream(event):
                            logger().debug("Event #%d pushed to Redis Stream: %s -> %s", count,
                                         event.get('src_ip'), event.get('dst_ip'))
                        else:
                            # Fallback: direct callback
                            event_callback(event)
                            logger().debug("Event #%d (fallback callback): %s -> %s", count,
                                         event.get('src_ip'), event.get('dst_ip'))
                    else:
                        # Legacy JSONL file mode
                        if write_event(event):
                            event_count = get_event_count() + 1
                            set_event_count(event_count)
                            logger().info("Event #%d: %s:%s -> %s:%s (%s)",
                                        event_count,
                                        event.get('src_ip'), event.get('sport'),
                                        event.get('dst_ip'), event.get('dport'),
                                        event.get('action'))

            except socket.timeout:
                continue
            except Exception as e:
                logger().error(f"Error receiving data: {e}")
                continue

    except Exception as e:
        logger().error(f"Failed to start listener: {e}")
    finally:
        sock.close()
        # Close the JSONL writer only in file mode
        if not callback_mode and _jsonl_writer is not None:
            _jsonl_writer.close()
        logger().info("Syslog listener stopped")


def _cleanup_jsonl_writer():
    """Close the JSONL writer on shutdown."""
    global _jsonl_writer
    if _jsonl_writer is not None:
        _jsonl_writer.close()
        _jsonl_writer = None


if __name__ == '__main__':
    import signal

    def _signal_handler(signum, frame):
        logger().info(f"Received signal {signum}, shutting down...")
        _cleanup_jsonl_writer()
        os._exit(0)

    signal.signal(signal.SIGTERM, _signal_handler)
    signal.signal(signal.SIGINT, _signal_handler)

    logger().info("Starting OPNsense Syslog Listener")
    run_syslog_listener()


# ============================================================
# Agent.py compatibility wrapper
# ============================================================


class SyslogListener:
    """UDP syslog listener that passes parsed events directly to a callback."""
    
    def __init__(self, config, event_callback=None):
        """
        Args:
            config: Config object with syslog_port
            event_callback: callable(event_dict) -> None
                           Called directly for each parsed event.
                           If None, falls back to writing JSONL (legacy).
        """
        self.config = config
        self.event_callback = event_callback
        self._thread = None
        self._running = False
    
    def start(self):
        """Start the syslog UDP listener in a background thread. Returns True on success."""
        try:
            # Override defaults from config
            self.UDP_PORT = self.config.syslog_port
            
            self._running = True
            self._thread = threading.Thread(target=self._run, daemon=True)
            self._thread.start()
            logger().info("Syslog listener started on UDP port %s", self.UDP_PORT)
            return True
        except Exception as e:
            logger().warning("Failed to start syslog listener: %s", e)
            self._running = False
            return False
    
    def _run(self):
        """Run the syslog listener loop.

        Binds to all interfaces for syslog reception from OPNsense.
        This is safe — firewalled to trusted hosts only.
        """
        bind_host = os.getenv("SYSLOG_BIND", "0.0.0.0")
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((bind_host, self.UDP_PORT))
            
            count = 0
            while self._running:
                try:
                    sock.settimeout(1.0)
                    data, addr = sock.recvfrom(65535)
                    line = data.decode('utf-8', errors='replace').strip()
                    
                    if not line:
                        continue
                    
                    event = parse_syslog_line(line)
                    if event:
                        count += 1
                        # Try Redis Stream first when enabled, fall back to callback
                        if REDIS_STREAM_ENABLED and push_to_redis_stream(event):
                            logger().debug("Event #%d pushed to Redis Stream: %s -> %s", count,
                                         event.get('src_ip'), event.get('dst_ip'))
                        elif self.event_callback:
                            # Direct callback — no JSONL file
                            self.event_callback(event)
                            logger().debug("Event #%d: %s -> %s", count,
                                         event.get('src_ip'), event.get('dst_ip'))
                        else:
                            # Legacy fallback: write JSONL
                            _init_event_counter()
                            write_event(event)
                            event_count = get_event_count() + 1
                            set_event_count(event_count)
                except socket.timeout:
                    continue
                except Exception as e:
                    logger().warning("Syslog listener error: %s", e)
            sock.close()
        except Exception as e:
            logger().error("Syslog listener thread failed: %s", e)
    
    def stop(self):
        """Stop the syslog listener."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
