#!/usr/bin/env python3
"""
Self-health monitoring for the OPNsense Anomaly Detection Agent.

Provides:
- System metrics collection (memory, CPU, load average via /proc)
- Periodic self-check with configurable interval
- Degraded state tracking and Discord alerting on health failures
"""

from __future__ import annotations

import json
import logging
import os
import re
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


def get_db_size_bytes() -> int:
    """Query PostgreSQL for current database size in bytes.

    Returns 0 if database is unreachable.
    """
    try:
        import psycopg2
        import os

        db_host = os.environ.get("DB_HOST", "localhost")
        db_port = os.environ.get("DB_PORT", "5432")
        db_name = os.environ.get("DB_NAME", "opnsense")
        db_user = os.environ.get("DB_USER", "opnsense")
        db_pass = os.environ.get("DB_PASSWORD", "opnsense")

        conn = psycopg2.connect(
            host=db_host, port=db_port, dbname=db_name,
            user=db_user, password=db_pass, connect_timeout=5
        )
        cur = conn.cursor()
        cur.execute("SELECT pg_database_size(current_database())")
        size = cur.fetchone()[0]
        cur.close()
        conn.close()
        return size
    except Exception as e:
        logger.debug("DB size query failed: %s", e)
        return 0


def get_redis_memory() -> Dict[str, Any]:
    """Query Redis INFO memory for memory usage stats.

    Returns a dict with:
      - used_mb: RSS memory used by Redis
      - peak_mb: Peak RSS memory
      - max_mb: maxmemory configured (0 = unlimited)
      - connected_clients: active client connections
      - status: 'ok' | 'warning' | 'unavailable'

    Returns {"status": "unavailable"} if Redis is not reachable.
    """
    try:
        import os
        redis_url = os.environ.get("REDIS_URL", "redis://redis:6379/0")
        try:
            import redis as redis_lib
        except ImportError:
            return {"status": "unavailable", "reason": "redis module not installed"}

        r = redis_lib.from_url(redis_url, socket_timeout=2, decode_responses=True)
        info = r.info("memory")
        used_bytes = info.get("used_memory_rss", info.get("used_memory", 0))
        peak_bytes = info.get("used_memory_peak", 0)
        max_bytes = info.get("maxmemory", 0)

        # Get connected clients
        server_info = r.info("clients")
        connected = server_info.get("connected_clients", 0)

        result = {
            "used_mb": round(used_bytes / (1024**2), 1),
            "peak_mb": round(peak_bytes / (1024**2), 1),
            "max_mb": round(max_bytes / (1024**2), 1) if max_bytes > 0 else 0.0,
            "connected_clients": connected,
            "status": "ok",
        }

        # Check if Redis is hitting maxmemory
        if max_bytes > 0:
            pct = (used_bytes / max_bytes * 100) if max_bytes > 0 else 0
            result["pct_of_max"] = round(pct, 1)
            if pct >= 95:
                result["status"] = "critical"
            elif pct >= 90:
                result["status"] = "warning"

        return result
    except Exception as e:
        logger.debug("Redis memory query failed: %s", e)
        return {"status": "unavailable", "reason": str(e)}


def get_disk_usage(path: str = "/app") -> Dict[str, Any]:
    """Get disk usage for the given path."""
    try:
        import shutil
        total, used, free = shutil.disk_usage(path)
        return {
            "total_mb": round(total / (1024**2), 1),
            "used_mb": round(used / (1024**2), 1),
            "free_mb": round(free / (1024**2), 1),
            "pct_used": round(used / total * 100, 1) if total > 0 else 0.0,
        }
    except Exception as e:
        return {"error": str(e)}


def get_system_metrics(db_size: bool = True, disk: bool = True, redis_memory: bool = False) -> Dict[str, Any]:
    """Collect system-level metrics from /proc (no psutil dependency).

    Returns a dict with:
      - memory: {total_mb, used_mb, free_mb, cached_mb, pct_used}
      - cpu: {usage_pct}  (sampled over 0.5s)
      - load_avg: {1m, 5m, 15m}
      - db_size: {bytes, mb}  (optional, if db_size=True)
      - disk: {total_mb, used_mb, free_mb, pct_used}  (optional, if disk=True)
      - redis: {used_mb, peak_mb, max_mb, connected_clients, status}  (optional, if redis_memory=True)
    """
    result: Dict[str, Any] = {}

    # --- Memory from /proc/meminfo ---
    try:
        meminfo: Dict[str, int] = {}
        with open("/proc/meminfo", "r") as f:
            for line in f:
                parts = line.split()
                key = parts[0].rstrip(":")
                value = int(parts[1])  # kB
                meminfo[key] = value

        total_kb = meminfo.get("MemTotal", 0)
        free_kb = meminfo.get("MemFree", 0)
        available_kb = meminfo.get("MemAvailable", free_kb)
        cached_kb = meminfo.get("Cached", 0) + meminfo.get("Buffers", 0)
        used_kb = total_kb - available_kb
        pct = (used_kb / total_kb * 100) if total_kb > 0 else 0.0

        result["memory"] = {
            "total_mb": round(total_kb / 1024, 1),
            "used_mb": round(used_kb / 1024, 1),
            "free_mb": round(available_kb / 1024, 1),
            "cached_mb": round(cached_kb / 1024, 1),
            "pct_used": round(pct, 1),
        }
    except Exception as e:
        result["memory"] = {"error": str(e)}

    # --- CPU usage (two samples 0.5s apart from /proc/stat) ---
    try:
        def _read_cpu_times() -> tuple:
            with open("/proc/stat", "r") as f:
                line = f.readline()
            # cpu  user nice system idle iowait irq softirq steal
            parts = line.split()[1:]
            times = tuple(int(x) for x in parts)
            return times

        t1 = _read_cpu_times()
        time.sleep(0.5)
        t2 = _read_cpu_times()

        delta = [b - a for a, b in zip(t1, t2)]
        total_delta = sum(delta)
        idle_delta = delta[3] if len(delta) > 3 else 0
        usage = (1.0 - idle_delta / total_delta) * 100 if total_delta > 0 else 0.0

        result["cpu"] = {"usage_pct": round(usage, 1)}
    except Exception as e:
        result["cpu"] = {"error": str(e)}

    # --- Load average from /proc/loadavg ---
    try:
        with open("/proc/loadavg", "r") as f:
            parts = f.read().split()
        result["load_avg"] = {
            "1m": float(parts[0]),
            "5m": float(parts[1]),
            "15m": float(parts[2]),
        }
    except Exception as e:
        result["load_avg"] = {"error": str(e)}

    # --- Database size ---
    if db_size:
        db_size_bytes = get_db_size_bytes()
        result["db_size"] = {
            "bytes": db_size_bytes,
            "mb": round(db_size_bytes / (1024**2), 1) if db_size_bytes > 0 else 0.0,
        }

    # --- Disk usage ---
    if disk:
        result["disk"] = get_disk_usage()

    # --- Redis memory ---
    if redis_memory:
        result["redis"] = get_redis_memory()

    return result


class HealthMonitor:
    """Periodic self-check that logs degraded state and alerts via Discord.

    Usage:
        monitor = HealthMonitor(agent, discord_bot, interval=300)
        monitor.start()
        # ... later ...
        monitor.stop()
    """

    # Thresholds for "degraded" classification
    MEMORY_WARN_PCT = 80.0
    MEMORY_CRIT_PCT = 95.0
    CPU_WARN_PCT = 90.0
    CPU_CRIT_PCT = 98.0
    EVENT_BUFFER_WARN = 5000
    EVENT_BUFFER_CRIT = 20000
    LOAD_WARN_MULTIPLIER = 2.0  # load > N * cpu_count
    DB_SIZE_WARN_MB = 2048     # 2 GB
    DB_SIZE_CRIT_MB = 5120     # 5 GB
    DISK_WARN_PCT = 90.0
    DISK_CRIT_PCT = 95.0
    REDIS_MAXMEM_WARN_PCT = 80.0
    REDIS_MAXMEM_CRIT_PCT = 95.0

    def __init__(
        self,
        agent: Any,
        discord_bot: Any,
        interval: int = 300,
        alert_cooldown: int = 3600,
    ):
        """
        Args:
            agent: AnomalyAgent instance (for event buffer, db access)
            discord_bot: DiscordBot instance (for alerting)
            interval: seconds between health checks
            alert_cooldown: minimum seconds between Discord alerts
        """
        self.agent = agent
        self.discord_bot = discord_bot
        self.interval = max(30, interval)  # minimum 30s
        self.alert_cooldown = alert_cooldown
        self._shutdown = threading.Event()
        self._thread: Optional[threading.Thread] = None

        # Degraded state tracking
        self._last_status: str = "healthy"
        self._last_alert_time: float = 0.0
        self._consecutive_degraded: int = 0
        self._lock = threading.Lock()

        # Load cpu_count for load average threshold
        try:
            self._cpu_count = os.cpu_count() or 1
        except Exception:
            self._cpu_count = 1

    # ── Public API ──────────────────────────────────────────────────

    def start(self) -> None:
        """Start the background health check thread."""
        if self._thread is not None and self._thread.is_alive():
            logger.info("Health monitor already running")
            return
        self._thread = threading.Thread(target=self._loop, daemon=True, name="health-monitor")
        self._thread.start()
        logger.info("Health monitor started (interval=%ds, alert_cooldown=%ds)", self.interval, self.alert_cooldown)

    def stop(self) -> None:
        """Stop the background health check thread."""
        self._shutdown.set()
        if self._thread:
            self._thread.join(timeout=10)
        logger.info("Health monitor stopped")

    def get_status(self) -> Dict[str, Any]:
        """Return current health status (non-blocking)."""
        with self._lock:
            return {
                "status": self._last_status,
                "consecutive_degraded": self._consecutive_degraded,
                "last_check_time": datetime.fromtimestamp(time.time(), tz=timezone.utc).isoformat() if self._thread else None,
            }

    def run_check(self) -> Dict[str, Any]:
        """Run a single health check synchronously. Returns the result dict."""
        issues: list[str] = []
        details: Dict[str, Any] = {}

        # 1. System metrics
        sys_metrics = get_system_metrics()
        details["system"] = sys_metrics

        # Memory check
        mem = sys_metrics.get("memory", {})
        if "error" not in mem:
            pct = mem.get("pct_used", 0)
            if pct >= self.MEMORY_CRIT_PCT:
                issues.append(f"CRITICAL: memory at {pct}%")
            elif pct >= self.MEMORY_WARN_PCT:
                issues.append(f"WARNING: memory at {pct}%")

        # CPU check
        cpu = sys_metrics.get("cpu", {})
        if "error" not in cpu:
            usage = cpu.get("usage_pct", 0)
            if usage >= self.CPU_CRIT_PCT:
                issues.append(f"CRITICAL: CPU at {usage}%")
            elif usage >= self.CPU_WARN_PCT:
                issues.append(f"WARNING: CPU at {usage}%")

        # Load average check
        load = sys_metrics.get("load_avg", {})
        if "error" not in load:
            load1 = load.get("1m", 0)
            threshold = self._cpu_count * self.LOAD_WARN_MULTIPLIER
            if load1 > threshold:
                issues.append(f"WARNING: load avg {load1:.1f} > {threshold:.0f} ({self._cpu_count} CPUs)")

        # 2. Event buffer depth
        try:
            buffer_depth = len(self.agent._event_buffer)
            details["event_buffer"] = {"depth": buffer_depth}
            if buffer_depth >= self.EVENT_BUFFER_CRIT:
                issues.append(f"CRITICAL: event buffer depth {buffer_depth}")
            elif buffer_depth >= self.EVENT_BUFFER_WARN:
                issues.append(f"WARNING: event buffer depth {buffer_depth}")
        except Exception as e:
            issues.append(f"ERROR: cannot read event buffer: {e}")

        # 2b. Database size
        db_info = sys_metrics.get("db_size", {})
        if "error" not in db_info:
            db_mb = db_info.get("mb", 0)
            if db_mb > 0:
                details["db_size"] = db_info
                if db_mb >= self.DB_SIZE_CRIT_MB:
                    issues.append(f"CRITICAL: database size {db_mb:.0f} MB")
                elif db_mb >= self.DB_SIZE_WARN_MB:
                    issues.append(f"WARNING: database size {db_mb:.0f} MB")

        # 2c. Disk usage
        disk_info = sys_metrics.get("disk", {})
        if "error" not in disk_info:
            details["disk"] = disk_info
            disk_pct = disk_info.get("pct_used", 0)
            if disk_pct >= self.DISK_CRIT_PCT:
                issues.append(f"CRITICAL: disk at {disk_pct}%")
            elif disk_pct >= self.DISK_WARN_PCT:
                issues.append(f"WARNING: disk at {disk_pct}%")

        # 2d. Redis memory
        redis_info = get_redis_memory()
        details["redis"] = redis_info
        if redis_info.get("status") != "unavailable":
            pct_of_max = redis_info.get("pct_of_max", 0)
            if pct_of_max >= self.REDIS_MAXMEM_CRIT_PCT:
                issues.append(f"CRITICAL: Redis memory at {pct_of_max}% of maxmemory")
            elif pct_of_max >= self.REDIS_MAXMEM_WARN_PCT:
                issues.append(f"WARNING: Redis memory at {pct_of_max}% of maxmemory")

        # 3. Database connectivity
        db_ok = True
        conn = None
        try:
            if self.agent.db:
                conn = self.agent.db.connect()
                if conn:
                    cur = conn.cursor()
                    cur.execute("SELECT 1")
                    cur.close()
                else:
                    db_ok = False
            else:
                db_ok = False
        except Exception as e:
            db_ok = False
            issues.append(f"ERROR: database check failed: {e}")
        finally:
            if conn:
                self.agent.db.putconn(conn)
        details["database"] = {"connected": db_ok}

        # 3b. Connection pool metrics
        pool = None
        pool_info: Dict[str, Any] = {}
        try:
            from eventdb import EventDatabase
            pool = EventDatabase._pool
            if pool:
                used = len(getattr(pool, "_used", {}))
                available = len(getattr(pool, "_pool", []))
                max_conn = pool.maxconn
                pool_info = {
                    "pool_active": used,
                    "pool_available": available,
                    "pool_max": max_conn,
                    "pool_utilization_pct": round(used / max_conn * 100, 1) if max_conn else 0.0,
                }
                details["pool"] = pool_info
                # Warn if pool utilization is high
                if max_conn:
                    util_pct = used / max_conn * 100
                    if util_pct >= 90:
                        issues.append(f"CRITICAL: connection pool at {util_pct:.0f}% ({used}/{max_conn})")
                    elif util_pct >= 70:
                        issues.append(f"WARNING: connection pool at {util_pct:.0f}% ({used}/{max_conn})")
        except Exception as e:
            logger.debug("Pool metrics check failed: %s", e)

        # 4. Determine overall status
        if any("CRITICAL" in i for i in issues):
            status = "critical"
        elif any("ERROR" in i for i in issues):
            status = "degraded"
        elif issues:
            status = "warning"
        else:
            status = "healthy"

        # Update state
        with self._lock:
            prev_status = self._last_status
            self._last_status = status

            if status in ("degraded", "critical"):
                self._consecutive_degraded += 1
            else:
                self._consecutive_degraded = 0

        # Log
        if issues:
            logger.warning(
                "Health check: %s (prev=%s) pool=[active=%s/avail=%s/%s] — %s",
                status, prev_status,
                pool_info.get("pool_active", "?"),
                pool_info.get("pool_available", "?"),
                pool_info.get("pool_max", "?"),
                "; ".join(issues),
            )
        else:
            logger.info(
                "Health check: %s (prev=%s) pool=[active=%s/avail=%s/%s] — all clear",
                status, prev_status,
                pool_info.get("pool_active", "?"),
                pool_info.get("pool_available", "?"),
                pool_info.get("pool_max", "?"),
            )

        # Discord alert on state change to degraded/critical (with cooldown)
        now = time.time()
        if status in ("degraded", "critical") and prev_status == "healthy":
            with self._lock:
                if now - self._last_alert_time >= self.alert_cooldown:
                    self._last_alert_time = now
                    self._send_alert(status, issues, details)
        # Also alert if consecutive degraded count hits threshold (3 checks = ~15 min)
        elif status in ("degraded", "critical") and self._consecutive_degraded >= 3:
            with self._lock:
                if now - self._last_alert_time >= self.alert_cooldown:
                    self._last_alert_time = now
                    self._send_alert(status, issues, details)

        return {
            "status": status,
            "issues": issues,
            "details": details,
        }

    # ── Private ─────────────────────────────────────────────────────

    def _loop(self) -> None:
        """Background loop: run check every `interval` seconds."""
        while not self._shutdown.is_set():
            try:
                self.run_check()
            except Exception as e:
                logger.error("Health check loop error: %s", e, exc_info=True)
            self._shutdown.wait(self.interval)

    def _send_alert(self, status: str, issues: list[str], details: Dict[str, Any]) -> None:
        """Send a health alert to Discord."""
        issue_text = "\n".join(f"• {i}" for i in issues)
        message = (
            f"**⚠️ Agent health: {status.upper()}**\n"
            f"```\n"
            f"Issues:\n{issue_text}\n"
            f"```\n"
            f"Consecutive degraded checks: {self._consecutive_degraded}"
        )
        try:
            # Use send_message for simple text alerts
            if hasattr(self.discord_bot, "send_message"):
                self.discord_bot.send_message(message)
            elif hasattr(self.discord_bot, "send_alert"):
                self.discord_bot.send_alert({
                    "type": "health_alert",
                    "severity": status.upper(),
                    "description": message,
                })
            logger.info("Health alert sent to Discord: %s", status)
        except Exception as e:
            logger.error("Failed to send health alert to Discord: %s", e)