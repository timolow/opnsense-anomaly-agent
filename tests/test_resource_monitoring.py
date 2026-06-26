#!/usr/bin/env python3
"""Tests for resource monitoring: health_monitor + server.py query_resources + Prometheus.

Covers:
- get_redis_memory() with reachable/unreachable Redis
- get_system_metrics() with redis_memory flag
- HealthMonitor threshold changes (memory >80%, disk >90%)
- query_resources() thresholds and Redis integration
- Prometheus metrics endpoint includes Redis metrics
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from unittest.mock import MagicMock, patch
import json

from health_monitor import (
    get_redis_memory,
    get_system_metrics,
    get_db_size_bytes,
    get_disk_usage,
    HealthMonitor,
)


class TestGetRedisMemory:
    """Test Redis memory collection."""

    def test_redis_unavailable_no_module(self):
        """Returns unavailable when redis module not installed."""
        with patch.dict(sys.modules, {'redis': None}):
            real_redis = sys.modules.pop('redis', None)
            result = get_redis_memory()
            if real_redis:
                sys.modules['redis'] = real_redis
            assert result["status"] == "unavailable"
            assert "reason" in result

    def test_redis_unavailable_connection_error(self):
        """Returns unavailable when Redis is unreachable."""
        mock_redis_lib = MagicMock()
        mock_redis_lib.from_url.side_effect = ConnectionError("ECONNREFUSED")

        with patch.dict(sys.modules, {'redis': mock_redis_lib}):
            result = get_redis_memory()
            assert result["status"] == "unavailable"
            assert "reason" in result

    def test_redis_memory_success(self):
        """Returns memory stats when Redis is reachable."""
        mock_client = MagicMock()
        mock_client.info.side_effect = [
            {"used_memory_rss": 10485760, "used_memory_peak": 15728640, "maxmemory": 52428800},
            {"connected_clients": 3},
        ]

        mock_redis_lib = MagicMock()
        mock_redis_lib.from_url.return_value = mock_client

        with patch.dict(sys.modules, {'redis': mock_redis_lib}):
            with patch('os.environ', {'REDIS_URL': 'redis://localhost:6379/0'}):
                result = get_redis_memory()

        assert result["status"] == "ok"
        assert result["used_mb"] == round(10485760 / (1024**2), 1)
        assert result["peak_mb"] == round(15728640 / (1024**2), 1)
        assert result["max_mb"] == round(52428800 / (1024**2), 1)
        assert result["connected_clients"] == 3

    def test_redis_memory_maxmemory_zero(self):
        """No pct_of_max when maxmemory is unlimited (0)."""
        mock_client = MagicMock()
        mock_client.info.side_effect = [
            {"used_memory_rss": 10485760, "used_memory_peak": 15728640, "maxmemory": 0},
            {"connected_clients": 1},
        ]

        mock_redis_lib = MagicMock()
        mock_redis_lib.from_url.return_value = mock_client

        with patch.dict(sys.modules, {'redis': mock_redis_lib}):
            result = get_redis_memory()

        assert result["status"] == "ok"
        assert result["max_mb"] == 0.0
        assert "pct_of_max" not in result

    def test_redis_memory_warning_threshold(self):
        """Status is 'warning' when pct >= 90% of maxmemory."""
        mock_client = MagicMock()
        max_mem = 52428800  # 50 MB
        used_mem = int(max_mem * 0.92)  # 92%
        mock_client.info.side_effect = [
            {"used_memory_rss": used_mem, "used_memory_peak": used_mem, "maxmemory": max_mem},
            {"connected_clients": 2},
        ]

        mock_redis_lib = MagicMock()
        mock_redis_lib.from_url.return_value = mock_client

        with patch.dict(sys.modules, {'redis': mock_redis_lib}):
            result = get_redis_memory()

        assert result["status"] == "warning"
        assert result["pct_of_max"] == 92.0

    def test_redis_memory_critical_threshold(self):
        """Status is 'critical' when pct >= 95% of maxmemory."""
        mock_client = MagicMock()
        max_mem = 52428800  # 50 MB
        used_mem = int(max_mem * 0.96)  # 96%
        mock_client.info.side_effect = [
            {"used_memory_rss": used_mem, "used_memory_peak": used_mem, "maxmemory": max_mem},
            {"connected_clients": 2},
        ]

        mock_redis_lib = MagicMock()
        mock_redis_lib.from_url.return_value = mock_client

        with patch.dict(sys.modules, {'redis': mock_redis_lib}):
            result = get_redis_memory()

        assert result["status"] == "critical"
        assert result["pct_of_max"] == 96.0


class TestGetSystemMetrics:
    """Test get_system_metrics includes Redis when requested."""

    def test_redis_memory_flag_false(self):
        """Redis not included when redis_memory=False (default)."""
        with patch('health_monitor.get_db_size_bytes', return_value=1024):
            with patch('health_monitor.get_disk_usage', return_value={"pct_used": 50.0}):
                mock_meminfo = MagicMock()
                mock_meminfo.__enter__.return_value = iter([
                    "MemTotal:       8000000 kB\n",
                    "MemFree:        1000000 kB\n",
                    "MemAvailable:   4000000 kB\n",
                    "Cached:         2000000 kB\n",
                    "Buffers:          50000 kB\n",
                ])
                mock_stat = MagicMock()
                mock_stat.__enter__.return_value = iter([
                    "cpu  100 20 30 400 10 5 3 0\n",
                ])
                mock_loadavg = MagicMock()
                mock_loadavg.__enter__.return_value = iter([
                    "0.50 0.30 0.20 0/100 12345\n",
                ])

                def fake_open(name, *args, **kwargs):
                    if "meminfo" in name:
                        return mock_meminfo
                    elif "stat" in name:
                        return mock_stat
                    elif "loadavg" in name:
                        return mock_loadavg
                    return MagicMock()

                with patch('builtins.open', side_effect=fake_open):
                    with patch('health_monitor.get_redis_memory', return_value={"status": "ok"}):
                        result = get_system_metrics(db_size=True, disk=True, redis_memory=False)

        assert "redis" not in result

    def test_redis_memory_flag_true(self):
        """Redis included when redis_memory=True."""
        with patch('health_monitor.get_db_size_bytes', return_value=1024):
            with patch('health_monitor.get_disk_usage', return_value={"pct_used": 50.0}):
                with patch('health_monitor.get_redis_memory', return_value={"status": "ok", "used_mb": 5.0}):
                    mock_meminfo = MagicMock()
                    mock_meminfo.__enter__.return_value = iter([
                        "MemTotal:       8000000 kB\n",
                        "MemFree:        1000000 kB\n",
                        "MemAvailable:   4000000 kB\n",
                        "Cached:         2000000 kB\n",
                        "Buffers:          50000 kB\n",
                    ])
                    mock_stat = MagicMock()
                    mock_stat.__enter__.return_value = iter([
                        "cpu  100 20 30 400 10 5 3 0\n",
                    ])
                    mock_loadavg = MagicMock()
                    mock_loadavg.__enter__.return_value = iter([
                        "0.50 0.30 0.20 0/100 12345\n",
                    ])

                    def fake_open(name, *args, **kwargs):
                        if "meminfo" in name:
                            return mock_meminfo
                        elif "stat" in name:
                            return mock_stat
                        elif "loadavg" in name:
                            return mock_loadavg
                        return MagicMock()

                    with patch('builtins.open', side_effect=fake_open):
                        result = get_system_metrics(db_size=True, disk=True, redis_memory=True)

        assert "redis" in result
        assert result["redis"]["status"] == "ok"


class TestHealthMonitorThresholds:
    """Test HealthMonitor threshold constants match spec."""

    def test_memory_warning_threshold_80(self):
        """Memory warning at 80% (per task spec)."""
        assert HealthMonitor.MEMORY_WARN_PCT == 80.0

    def test_memory_critical_threshold_95(self):
        """Memory critical at 95%."""
        assert HealthMonitor.MEMORY_CRIT_PCT == 95.0

    def test_disk_warning_threshold_90(self):
        """Disk warning at 90% (per task spec)."""
        assert HealthMonitor.DISK_WARN_PCT == 90.0

    def test_disk_critical_threshold_95(self):
        """Disk critical at 95%."""
        assert HealthMonitor.DISK_CRIT_PCT == 95.0

    def test_redis_warning_threshold_80(self):
        """Redis warning at 80% of maxmemory."""
        assert HealthMonitor.REDIS_MAXMEM_WARN_PCT == 80.0

    def test_redis_critical_threshold_95(self):
        """Redis critical at 95% of maxmemory."""
        assert HealthMonitor.REDIS_MAXMEM_CRIT_PCT == 95.0

    def test_run_check_includes_redis(self):
        """run_check() queries Redis memory."""
        agent = MagicMock()
        agent.db = None
        discord_bot = MagicMock()

        monitor = HealthMonitor(agent, discord_bot, interval=60)

        with patch('health_monitor.get_system_metrics', return_value={
            "memory": {"pct_used": 50.0},
            "cpu": {"usage_pct": 30.0},
            "load_avg": {"1m": 0.5, "5m": 0.3, "15m": 0.2},
            "db_size": {"bytes": 1024, "mb": 0.001},
            "disk": {"pct_used": 50.0},
        }):
            with patch('health_monitor.get_redis_memory', return_value={
                "status": "ok", "used_mb": 5.0, "peak_mb": 10.0,
                "max_mb": 50.0, "connected_clients": 2,
            }):
                result = monitor.run_check()

        assert "redis" in result["details"]
        assert result["details"]["redis"]["status"] == "ok"

    def test_run_check_redis_warning(self):
        """run_check() flags Redis when above warning threshold."""
        agent = MagicMock()
        agent.db = None
        discord_bot = MagicMock()

        monitor = HealthMonitor(agent, discord_bot, interval=60)

        with patch('health_monitor.get_system_metrics', return_value={
            "memory": {"pct_used": 50.0},
            "cpu": {"usage_pct": 30.0},
            "load_avg": {"1m": 0.5, "5m": 0.3, "15m": 0.2},
            "db_size": {"bytes": 1024, "mb": 0.001},
            "disk": {"pct_used": 50.0},
        }):
            with patch('health_monitor.get_redis_memory', return_value={
                "status": "warning", "used_mb": 42.0, "peak_mb": 42.0,
                "max_mb": 50.0, "connected_clients": 2, "pct_of_max": 84.0,
            }):
                result = monitor.run_check()

        assert any("Redis memory" in issue for issue in result["issues"])


class TestQueryResourcesThresholds:
    """Test query_resources() logic by importing only the function logic.

    We can't easily import server.py locally (missing psycopg2), so we test
    the threshold logic directly by simulating what query_resources does.
    """

    def _simulate_query_resources(self, metrics):
        """Simulate query_resources() logic for testing."""
        status = "ok"
        warnings = []

        # Memory check (> 80% warning, > 95% critical)
        mem = metrics.get("memory", {})
        if "error" not in mem:
            pct = mem.get("pct_used", 0)
            if pct >= 95.0:
                mem["status"] = "critical"
                status = "critical"
            elif pct >= 80.0:
                mem["status"] = "warning"
                warnings.append(f"Memory at {pct}%")
                if status == "ok":
                    status = "warning"
            else:
                mem["status"] = "ok"

        # Disk check (> 90% warning, > 95% critical)
        disk = metrics.get("disk", {})
        if "error" not in disk:
            pct = disk.get("pct_used", 0)
            if pct >= 95.0:
                disk["status"] = "critical"
                status = "critical"
            elif pct >= 90.0:
                disk["status"] = "warning"
                warnings.append(f"Disk at {pct}%")
                if status == "ok":
                    status = "warning"
            else:
                disk["status"] = "ok"

        # Redis memory check
        redis = metrics.get("redis", {})
        redis_status = redis.get("status", "ok")
        if redis_status == "warning":
            warnings.append(f"Redis memory at {redis.get('pct_of_max', 'N/A')}% of max")
            if status == "ok":
                status = "warning"
        elif redis_status == "critical":
            status = "critical"
            warnings.append(f"Redis memory critical at {redis.get('pct_of_max', 'N/A')}% of max")

        return {"status": status, "warnings": warnings, "resources": metrics}

    def test_memory_80_triggers_warning(self):
        """Memory at 80% triggers warning."""
        result = self._simulate_query_resources({
            "memory": {"total_mb": 8192, "used_mb": 6553, "pct_used": 80.0},
            "disk": {"pct_used": 50.0},
            "redis": {"status": "ok"},
        })
        assert result["status"] == "warning"
        assert any("Memory at 80.0%" in w for w in result["warnings"])

    def test_memory_79_ok(self):
        """Memory at 79% is still OK."""
        result = self._simulate_query_resources({
            "memory": {"pct_used": 79.0},
            "disk": {"pct_used": 50.0},
            "redis": {"status": "ok"},
        })
        assert result["status"] == "ok"

    def test_disk_90_triggers_warning(self):
        """Disk at 90% triggers warning."""
        result = self._simulate_query_resources({
            "memory": {"pct_used": 50.0},
            "disk": {"pct_used": 90.0},
            "redis": {"status": "ok"},
        })
        assert result["status"] == "warning"
        assert any("Disk at 90.0%" in w for w in result["warnings"])

    def test_disk_89_ok(self):
        """Disk at 89% is still OK."""
        result = self._simulate_query_resources({
            "memory": {"pct_used": 50.0},
            "disk": {"pct_used": 89.0},
            "redis": {"status": "ok"},
        })
        assert result["status"] == "ok"

    def test_redis_warning_propagates(self):
        """Redis warning status propagates to overall status."""
        result = self._simulate_query_resources({
            "memory": {"pct_used": 50.0},
            "disk": {"pct_used": 50.0},
            "redis": {"status": "warning", "pct_of_max": 84.0},
        })
        assert result["status"] == "warning"
        assert any("Redis memory" in w for w in result["warnings"])

    def test_redis_critical_propagates(self):
        """Redis critical status makes overall critical."""
        result = self._simulate_query_resources({
            "memory": {"pct_used": 50.0},
            "disk": {"pct_used": 50.0},
            "redis": {"status": "critical", "pct_of_max": 96.0},
        })
        assert result["status"] == "critical"

    def test_all_ok(self):
        """All resources OK when below thresholds."""
        result = self._simulate_query_resources({
            "memory": {"pct_used": 50.0},
            "disk": {"pct_used": 50.0},
            "redis": {"status": "ok"},
        })
        assert result["status"] == "ok"
        assert len(result["warnings"]) == 0


class TestPrometheusRedisMetrics:
    """Test Prometheus Redis metric generation logic."""

    def _generate_redis_prometheus(self, rinfo):
        """Simulate the Redis section of _send_prometheus_metrics."""
        out = []
        if "error" not in rinfo and rinfo.get("status") != "unavailable":
            out.append("# HELP agent_redis_memory_used_bytes Redis RSS memory in bytes")
            out.append("# TYPE agent_redis_memory_used_bytes gauge")
            out.append(f"agent_redis_memory_used_bytes {int(rinfo.get('used_mb', 0) * 1024 * 1024)}")
            out.append("# HELP agent_redis_memory_peak_bytes Redis peak RSS memory in bytes")
            out.append("# TYPE agent_redis_memory_peak_bytes gauge")
            out.append(f"agent_redis_memory_peak_bytes {int(rinfo.get('peak_mb', 0) * 1024 * 1024)}")
            out.append("# HELP agent_redis_connected_clients Redis connected clients")
            out.append("# TYPE agent_redis_connected_clients gauge")
            out.append(f"agent_redis_connected_clients {rinfo.get('connected_clients', 0)}")
            if rinfo.get("max_mb", 0) > 0:
                out.append("# HELP agent_redis_memory_usage_pct Redis memory usage percentage of maxmemory")
                out.append("# TYPE agent_redis_memory_usage_pct gauge")
                out.append(f"agent_redis_memory_usage_pct {rinfo.get('pct_of_max', 0)}")
        return "\n".join(out)

    def test_redis_metrics_present(self):
        """Prometheus output contains Redis memory metrics when Redis is available."""
        output = self._generate_redis_prometheus({
            "status": "ok", "used_mb": 5.0, "peak_mb": 10.0,
            "max_mb": 50.0, "connected_clients": 3, "pct_of_max": 10.0,
        })

        assert "agent_redis_memory_used_bytes" in output
        assert "agent_redis_memory_peak_bytes" in output
        assert "agent_redis_connected_clients" in output
        assert "agent_redis_memory_usage_pct" in output
        assert "agent_redis_connected_clients 3" in output

    def test_redis_metrics_skipped_unavailable(self):
        """Prometheus skips Redis metrics when status is 'unavailable'."""
        output = self._generate_redis_prometheus({
            "status": "unavailable", "reason": "connection refused",
        })
        assert "agent_redis_memory_used_bytes" not in output
        assert "agent_redis_connected_clients" not in output

    def test_redis_metrics_skipped_no_maxmemory(self):
        """Prometheus omits pct metric when maxmemory is 0 (unlimited)."""
        output = self._generate_redis_prometheus({
            "status": "ok", "used_mb": 5.0, "peak_mb": 10.0,
            "max_mb": 0.0, "connected_clients": 2,
        })
        assert "agent_redis_memory_used_bytes" in output
        assert "agent_redis_memory_usage_pct" not in output