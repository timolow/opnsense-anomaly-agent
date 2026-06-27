#!/usr/bin/env python3
"""
Test data seeder for OPNsense Anomaly Agent.

Injects identifiable test records across all data sources with marker IPs
(192.168.100.x / 10.255.255.x) so E2E tests can verify source -> DB -> API -> UI
data flow without touching real production data.

All seeded records carry a `test_marker` field (JSONB detail on anomalies,
raw_message prefix on events) so they are trivially filterable.

Usage as module:
    from test_data_seeder import TestSeeder
    seeder = TestSeeder()
    seeder.seed_all()
    # ... run E2E checks ...
    seeder.cleanup()

Usage as script:
    python test_data_seeder.py          # seed + print summary
    python test_data_seeder.py --seed   # same
    python test_data_seeder.py --clean  # remove all test data
    python test_data_seeder.py --dry-run  # print what would be inserted
"""

from __future__ import annotations

import os
import sys
import json
import argparse
import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Marker IPs — 192.168.100.x range (RFC1918, never in production WAN/LAN)
# ---------------------------------------------------------------------------
MARKER_IP_BASE = "192.168.100"
TEST_MARKER_PREFIX = "TEST_SEED"

# Each test scenario gets its own source IP so it's uniquely identifiable.
TEST_IPS: Dict[str, str] = {
    "normal_tcp":       f"{MARKER_IP_BASE}.1",
    "normal_udp":       f"{MARKER_IP_BASE}.2",
    "port_scan":        f"{MARKER_IP_BASE}.10",
    "syn_flood":        f"{MARKER_IP_BASE}.11",
    "brute_force_ssh":  f"{MARKER_IP_BASE}.12",
    "probe_xmas":       f"{MARKER_IP_BASE}.20",
    "probe_null":       f"{MARKER_IP_BASE}.21",
    "probe_fin":        f"{MARKER_IP_BASE}.22",
    "high_volume":      f"{MARKER_IP_BASE}.50",
    "wan_outbound":     f"{MARKER_IP_BASE}.60",
    "lan_internal":     f"{MARKER_IP_BASE}.70",
    "zenarmor":         f"{MARKER_IP_BASE}.80",
    "ids_trigger":      f"{MARKER_IP_BASE}.81",
    "nginx_web":        f"{MARKER_IP_BASE}.82",
    "service_dhcp":     f"{MARKER_IP_BASE}.90",
    "wan_flap":         f"{MARKER_IP_BASE}.99",
}

# Destination IPs used in test events
DST_IP_LAN   = f"{MARKER_IP_BASE}.101"
DST_IP_SERVER = f"{MARKER_IP_BASE}.102"
DST_IP_WAN   = "8.8.8.8"

# Test rule names
TEST_RULES = [
    "TEST_SEED_RULE_ALLOW_LAN",
    "TEST_SEED_RULE_BLOCK_WAN",
    "TEST_SEED_RULE_BLOCK_SSH",
    "TEST_SEED_RULE_DEFAULT",
]

# ---------------------------------------------------------------------------
# TestSeeder
# ---------------------------------------------------------------------------
class TestSeeder:
    """Injects and cleans up identifiable test data for E2E verification."""

    def __init__(self, host: Optional[str] = None, port: Optional[int] = None,
                 database: Optional[str] = None, user: Optional[str] = None,
                 password: Optional[str] = None):
        self.host = host or os.environ.get("DB_HOST", "postgres")
        self.port = port or int(os.environ.get("DB_PORT", "5432"))
        self.database = database or os.environ.get("DB_NAME", "anomaly_agent")
        self.user = user or os.environ.get("DB_USER", "anomaly_agent")
        self.password = password or os.environ.get("DB_PASSWORD") or os.environ.get("DB_PASS", "anomaly_agent_secret")
        self._inserted_event_ids: List[int] = []
        self._inserted_anomaly_ids: List[int] = []
        self._inserted_drift_ids: List[int] = []
        self._inserted_baselines: int = 0
        self._inserted_threat_profiles: int = 0
        self._inserted_rule_feedback: int = 0
        self._inserted_rule_baselines: int = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def seed_all(self, hours_ago: float = 1.0) -> Dict[str, int]:
        """Seed test data across ALL tables. Returns insertion counts."""
        counts: Dict[str, int] = {}
        counts["events"] = self._seed_events(hours_ago)
        counts["anomalies"] = self._seed_anomalies(hours_ago)
        counts["baselines"] = self._seed_baselines(hours_ago)
        counts["drift_events"] = self._seed_drift_events(hours_ago)
        counts["threat_profiles"] = self._seed_threat_profiles(hours_ago)
        counts["rule_feedback"] = self._seed_rule_feedback(hours_ago)
        counts["rule_baselines"] = self._seed_rule_baselines(hours_ago)
        logger.info("TestSeeder.seed_all() complete: %s", counts)
        return counts

    def seed_normal_traffic(self, count: int = 50, hours_ago: float = 1.0) -> int:
        """Seed realistic normal TCP/UDP traffic events."""
        events = self._make_normal_traffic(count, hours_ago)
        return self._bulk_insert_events(events)

    def seed_port_scan(self, src_ip: Optional[str] = None, ports: Optional[List[int]] = None,
                       hours_ago: float = 0.5) -> int:
        """Seed a vertical port scan from src_ip -> DST_IP_SERVER."""
        events = self._make_port_scan(src_ip or TEST_IPS["port_scan"], ports, hours_ago)
        return self._bulk_insert_events(events)

    def seed_syn_flood(self, src_ip: Optional[str] = None, count: int = 100,
                       hours_ago: float = 0.25) -> int:
        """Seed SYN flood events."""
        events = self._make_syn_flood(src_ip or TEST_IPS["syn_flood"], count, hours_ago)
        return self._bulk_insert_events(events)

    def seed_brute_force(self, src_ip: Optional[str] = None, count: int = 30,
                         hours_ago: float = 0.5) -> int:
        """Seed SSH brute force attempts."""
        events = self._make_brute_force(src_ip or TEST_IPS["brute_force_ssh"], count, hours_ago)
        return self._bulk_insert_events(events)

    def seed_high_volume(self, count: int = 500, hours_ago: float = 1.0) -> int:
        """Seed high-volume traffic from a single IP (triggers alert threshold)."""
        events = self._make_high_volume(count, hours_ago)
        return self._bulk_insert_events(events)

    def seed_anomalies(self, hours_ago: float = 0.5) -> int:
        """Seed test anomalies covering all attack types."""
        anomalies = self._make_anomalies(hours_ago)
        return self._bulk_insert_anomalies(anomalies)

    def seed_mixed(self, hours_ago: float = 1.0) -> Dict[str, int]:
        """Seed a mix of traffic types for realistic-looking dashboard data."""
        counts: Dict[str, int] = {}
        counts["normal"] = self.seed_normal_traffic(200, hours_ago)
        counts["port_scan"] = self.seed_port_scan(hours_ago=hours_ago)
        counts["syn_flood"] = self.seed_syn_flood(count=50, hours_ago=hours_ago * 0.5)
        counts["brute_force"] = self.seed_brute_force(count=20, hours_ago=hours_ago * 0.3)
        counts["high_volume"] = self.seed_high_volume(300, hours_ago)
        counts["anomalies"] = self.seed_anomalies(hours_ago=hours_ago * 0.2)
        logger.info("TestSeeder.seed_mixed() complete: %s", counts)
        return counts

    def cleanup(self) -> Dict[str, int]:
        """Remove ALL seeded test data. Returns deletion counts."""
        counts: Dict[str, int] = {}
        with self._cursor() as cur:
            # Delete anomalies first (FK from events)
            cur.execute("DELETE FROM anomalies WHERE src_ip LIKE %s OR dst_ip LIKE %s",
                        (f"{MARKER_IP_BASE}.%", f"{MARKER_IP_BASE}.%"))
            counts["anomalies"] = cur.rowcount
            cur.execute("DELETE FROM anomalies WHERE description LIKE %s",
                        (f"{TEST_MARKER_PREFIX}%",))
            counts["anomalies_detail"] = cur.rowcount

            # Delete drift events
            cur.execute("DELETE FROM drift_events WHERE description LIKE %s",
                        (f"{TEST_MARKER_PREFIX}%",))
            counts["drift_events"] = cur.rowcount

            # Delete rule baselines
            cur.execute("DELETE FROM rule_baselines WHERE rule LIKE %s",
                        (f"{TEST_MARKER_PREFIX}%",))
            counts["rule_baselines"] = cur.rowcount

            # Delete baselines with test marker in metric
            cur.execute("DELETE FROM baselines WHERE metric LIKE %s",
                        (f"{TEST_MARKER_PREFIX}%",))
            counts["baselines"] = cur.rowcount

            # Delete rule feedback
            cur.execute("DELETE FROM rule_feedback WHERE rule_name LIKE %s OR reason LIKE %s",
                        (f"{TEST_MARKER_PREFIX}%", f"{TEST_MARKER_PREFIX}%"))
            counts["rule_feedback"] = cur.rowcount

            # Delete threat profiles
            cur.execute("DELETE FROM ip_threat_profiles WHERE ip LIKE %s",
                        (f"{MARKER_IP_BASE}.%",))
            counts["threat_profiles"] = cur.rowcount

            # Delete events last
            cur.execute("DELETE FROM events WHERE src_ip LIKE %s OR dst_ip LIKE %s OR raw_message LIKE %s OR rule_name LIKE %s",
                        (f"{MARKER_IP_BASE}.%", f"{MARKER_IP_BASE}.%",
                         f"{TEST_MARKER_PREFIX}%", f"{TEST_MARKER_PREFIX}%"))
            counts["events"] = cur.rowcount

        logger.info("TestSeeder.cleanup() complete: %s", counts)
        return counts

    def count_test_records(self) -> Dict[str, int]:
        """Count all test-marked records currently in the database."""
        counts: Dict[str, int] = {}
        with self._cursor() as cur:
            for table, col_patterns in [
                ("events", [(f"{MARKER_IP_BASE}.%",), (f"{MARKER_IP_BASE}.%",), (f"{TEST_MARKER_PREFIX}%",), (f"{TEST_MARKER_PREFIX}%")]),
                ("anomalies", [(f"{MARKER_IP_BASE}.%",), (f"{MARKER_IP_BASE}.%",), (f"{TEST_MARKER_PREFIX}%")]),
            ]:
                pass  # simplified below

        with self._cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM events WHERE src_ip LIKE %s OR dst_ip LIKE %s OR raw_message LIKE %s OR rule_name LIKE %s",
                        (f"{MARKER_IP_BASE}.%", f"{MARKER_IP_BASE}.%", f"{TEST_MARKER_PREFIX}%", f"{TEST_MARKER_PREFIX}%"))
            counts["events"] = cur.fetchone()[0]
            cur.execute("SELECT COUNT(*) FROM anomalies WHERE src_ip LIKE %s OR dst_ip LIKE %s OR description LIKE %s",
                        (f"{MARKER_IP_BASE}.%", f"{MARKER_IP_BASE}.%", f"{TEST_MARKER_PREFIX}%"))
            counts["anomalies"] = cur.fetchone()[0]
            cur.execute("SELECT COUNT(*) FROM baselines WHERE metric LIKE %s",
                        (f"{TEST_MARKER_PREFIX}%"))
            counts["baselines"] = cur.fetchone()[0]
            cur.execute("SELECT COUNT(*) FROM drift_events WHERE description LIKE %s",
                        (f"{TEST_MARKER_PREFIX}%"))
            counts["drift_events"] = cur.fetchone()[0]
            cur.execute("SELECT COUNT(*) FROM ip_threat_profiles WHERE ip LIKE %s",
                        (f"{MARKER_IP_BASE}%"))
            counts["threat_profiles"] = cur.fetchone()[0]
            cur.execute("SELECT COUNT(*) FROM rule_baselines WHERE rule LIKE %s",
                        (f"{TEST_MARKER_PREFIX}%"))
            counts["rule_baselines"] = cur.fetchone()[0]
        return counts

    # ------------------------------------------------------------------
    # Event factories
    # ------------------------------------------------------------------
    def _make_normal_traffic(self, count: int, hours_ago: float) -> List[Tuple]:
        """Generate normal TCP/UDP traffic events."""
        events: List[Tuple] = []
        base_ts = datetime.now(timezone.utc) - timedelta(hours=hours_ago)
        protocols = ["TCP", "UDP", "TCP", "TCP"]  # weight toward TCP
        actions = ["PASS", "PASS", "PASS", "BLOCK"]
        interfaces = ["em0", "em1", "igb0"]
        src_ips = [
            TEST_IPS["normal_tcp"], TEST_IPS["normal_udp"],
            TEST_IPS["lan_internal"],
        ]

        for i in range(count):
            ts = base_ts + timedelta(seconds=i * (hours_ago * 3600 / max(count, 1)))
            src_ip = src_ips[i % len(src_ips)]
            proto = protocols[i % len(protocols)]
            action = actions[i % len(actions)]
            dst_port = [80, 443, 53, 8080, 22, 3306, 8443][i % 7]
            iface = interfaces[i % len(interfaces)]

            events.append((
                ts,                          # timestamp
                src_ip,                       # src_ip
                DST_IP_LAN,                   # dst_ip
                f"test-host-{i % 5}.local",   # src_hostname
                "server.local",               # dst_hostname
                49152 + i,                    # src_port
                dst_port,                     # dst_port
                proto,                        # proto
                action,                       # action
                iface,                        # interface
                "inbound",                    # direction
                4,                            # version
                64,                           # ip_ttl
                128 + (i % 10) * 8,          # ip_total_length
                "SA" if proto == "TCP" else None,  # tcp_flags
                None, None, None, None,       # tcp_seq/ack/window/options
                None if proto == "TCP" else 64,  # udp_datalen
                None,                         # icmp_datalen
                f"{TEST_MARKER_PREFIX}|normal_traffic|seq={i}",  # raw_message
                TEST_RULES[i % len(TEST_RULES)],  # rule_name
                "filterlog",                  # log_type
            ))
        return events

    def _make_port_scan(self, src_ip: Optional[str] = None, ports: Optional[List[int]] = None,
                        hours_ago: float = 0.5) -> List[Tuple]:
        """Generate vertical port scan events."""
        if src_ip is None:
            src_ip = TEST_IPS["port_scan"]
        if ports is None:
            ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 3389, 5432, 8080, 8443]
        events: List[Tuple] = []
        base_ts = datetime.now(timezone.utc) - timedelta(hours=hours_ago)

        for i, port in enumerate(ports):
            ts = base_ts + timedelta(seconds=i)
            events.append((
                ts,
                src_ip,
                DST_IP_SERVER,
                None, None,
                50000 + i, port,
                "TCP", "BLOCK", "em0",
                "inbound", 4, 64, 60,
                "SYN", None, None, None, None,
                None, None,
                f"{TEST_MARKER_PREFIX}|port_scan|port={port}",
                TEST_RULES[1],  # BLOCK_WAN
                "filterlog",
            ))
        return events

    def _make_syn_flood(self, src_ip: Optional[str] = None, count: int = 100,
                        hours_ago: float = 0.25) -> List[Tuple]:
        """Generate SYN flood events (many SYN to same port)."""
        if src_ip is None:
            src_ip = TEST_IPS["syn_flood"]
        events: List[Tuple] = []
        base_ts = datetime.now(timezone.utc) - timedelta(hours=hours_ago)

        for i in range(count):
            ts = base_ts + timedelta(milliseconds=i * 100)
            events.append((
                ts,
                src_ip,
                DST_IP_SERVER,
                None, None,
                60000 + (i % 10000), 80,
                "TCP", "BLOCK", "em0",
                "inbound", 4, 128, 60,
                "SYN", None, None, None, None,
                None, None,
                f"{TEST_MARKER_PREFIX}|syn_flood|seq={i}",
                TEST_RULES[1],
                "filterlog",
            ))
        return events

    def _make_brute_force(self, src_ip: Optional[str] = None, count: int = 30,
                          hours_ago: float = 0.5) -> List[Tuple]:
        """Generate SSH brute force attempts."""
        if src_ip is None:
            src_ip = TEST_IPS["brute_force_ssh"]
        events: List[Tuple] = []
        base_ts = datetime.now(timezone.utc) - timedelta(hours=hours_ago)

        for i in range(count):
            ts = base_ts + timedelta(seconds=i * 2)
            events.append((
                ts,
                src_ip,
                DST_IP_SERVER,
                None, None,
                49152 + i, 22,
                "TCP", "BLOCK", "em0",
                "inbound", 4, 64, 80,
                "SYN", None, None, None, None,
                None, None,
                f"{TEST_MARKER_PREFIX}|brute_force_ssh|attempt={i}",
                TEST_RULES[2],  # BLOCK_SSH
                "filterlog",
            ))
        return events

    def _make_high_volume(self, count: int = 500, hours_ago: float = 1.0) -> List[Tuple]:
        """Generate high-volume traffic (triggers alert threshold >1000)."""
        events: List[Tuple] = []
        base_ts = datetime.now(timezone.utc) - timedelta(hours=hours_ago)
        src_ip = TEST_IPS["high_volume"]

        for i in range(count):
            ts = base_ts + timedelta(seconds=i * (hours_ago * 3600 / count))
            dst_port = [443, 80, 8080, 8443][i % 4]
            events.append((
                ts,
                src_ip,
                DST_IP_SERVER,
                None, None,
                40000 + (i % 25000), dst_port,
                "TCP", "PASS", "em0",
                "inbound", 4, 64, 1500,
                "SA", None, None, None, None,
                None, None,
                f"{TEST_MARKER_PREFIX}|high_volume|seq={i}",
                TEST_RULES[0],
                "filterlog",
            ))
        return events

    def _make_zenarmor_events(self, count: int = 10, hours_ago: float = 1.0) -> List[Tuple]:
        """Generate ZenArmor-style log events."""
        events: List[Tuple] = []
        base_ts = datetime.now(timezone.utc) - timedelta(hours=hours_ago)
        src_ip = TEST_IPS["zenarmor"]

        for i in range(count):
            ts = base_ts + timedelta(seconds=i * 30)
            events.append((
                ts, src_ip, DST_IP_LAN,
                None, None,
                50000 + i, 443,
                "TCP", "PASS", "em1",
                "inbound", 4, 64, 200,
                "SA", None, None, None, None,
                None, None,
                f"{TEST_MARKER_PREFIX}|zenarmor|policy=block_malware|seq={i}",
                TEST_RULES[0],
                "zenarmor",
            ))
        return events

    def _make_ids_events(self, count: int = 5, hours_ago: float = 0.5) -> List[Tuple]:
        """Generate IDS/Snort-style events."""
        events: List[Tuple] = []
        base_ts = datetime.now(timezone.utc) - timedelta(hours=hours_ago)
        src_ip = TEST_IPS["ids_trigger"]

        sigs = [
            "ET SCAN Potential SSH Scan",
            "ET POLICY Suspicious DNS Query",
            "ET TROJAN Known C2 Traffic",
            "ET EXPLOIT Buffer Overflow Attempt",
            "ET WEB_SERVER SQL Injection Attempt",
        ]

        for i in range(count):
            ts = base_ts + timedelta(seconds=i * 60)
            events.append((
                ts, src_ip, DST_IP_SERVER,
                None, None,
                55000 + i, [80, 443, 8080, 3306, 5432][i % 5],
                "TCP", "BLOCK", "em0",
                "inbound", 4, 64, 512,
                "SA", None, None, None, None,
                None, None,
                f"{TEST_MARKER_PREFIX}|ids|signature={sigs[i % len(sigs)]}|seq={i}",
                TEST_RULES[1],
                "ids",
            ))
        return events

    def _make_nginx_events(self, count: int = 10, hours_ago: float = 1.0) -> List[Tuple]:
        """Generate nginx-style web log events."""
        events: List[Tuple] = []
        base_ts = datetime.now(timezone.utc) - timedelta(hours=hours_ago)
        src_ip = TEST_IPS["nginx_web"]

        paths = ["/", "/api/v1/users", "/admin", "/.env", "/wp-admin", "/api/health", "/login", "/../../../etc/passwd"]
        status_codes = [200, 200, 301, 403, 404, 200, 200, 400]

        for i in range(count):
            ts = base_ts + timedelta(seconds=i * 15)
            events.append((
                ts, src_ip, DST_IP_SERVER,
                None, None,
                45000 + i, 443,
                "TCP", "PASS", "em1",
                "inbound", 4, 64, 256,
                "SA", None, None, None, None,
                None, None,
                f"{TEST_MARKER_PREFIX}|nginx|path={paths[i % len(paths)]}|status={status_codes[i % len(status_codes)]}",
                TEST_RULES[0],
                "nginx",
            ))
        return events

    # ------------------------------------------------------------------
    # Anomaly factories
    # ------------------------------------------------------------------
    def _make_anomalies(self, hours_ago: float = 0.5) -> List[Dict[str, Any]]:
        """Generate test anomalies covering all attack types."""
        ts = datetime.now(timezone.utc) - timedelta(hours=hours_ago)
        anomalies: List[Dict[str, Any]] = [
            # Port scan
            {
                "timestamp": ts,
                "attack_type": "PORT_SCAN",
                "severity": "HIGH",
                "src_ip": TEST_IPS["port_scan"],
                "dst_ip": DST_IP_SERVER,
                "dst_port": None,
                "proto": "TCP",
                "description": f"{TEST_MARKER_PREFIX}|port_scan|16 ports scanned on {DST_IP_SERVER}",
                "detail": {"marker": TEST_MARKER_PREFIX, "scan_type": "vertical", "ports_scanned": 16},
            },
            # SYN flood
            {
                "timestamp": ts + timedelta(minutes=5),
                "attack_type": "SYN_FLOOD",
                "severity": "CRITICAL",
                "src_ip": TEST_IPS["syn_flood"],
                "dst_ip": DST_IP_SERVER,
                "dst_port": 80,
                "proto": "TCP",
                "description": f"{TEST_MARKER_PREFIX}|syn_flood|100 SYN packets to port 80",
                "detail": {"marker": TEST_MARKER_PREFIX, "packet_count": 100, "target_port": 80},
            },
            # Brute force
            {
                "timestamp": ts + timedelta(minutes=10),
                "attack_type": "BRUTE_FORCE",
                "severity": "HIGH",
                "src_ip": TEST_IPS["brute_force_ssh"],
                "dst_ip": DST_IP_SERVER,
                "dst_port": 22,
                "proto": "TCP",
                "description": f"{TEST_MARKER_PREFIX}|brute_force|30 SSH attempts from {TEST_IPS['brute_force_ssh']}",
                "detail": {"marker": TEST_MARKER_PREFIX, "attempts": 30, "service": "ssh"},
            },
            # Probe - XMAS
            {
                "timestamp": ts + timedelta(minutes=15),
                "attack_type": "PROBE_XMAS",
                "severity": "MEDIUM",
                "src_ip": TEST_IPS["probe_xmas"],
                "dst_ip": DST_IP_SERVER,
                "dst_port": 445,
                "proto": "TCP",
                "description": f"{TEST_MARKER_PREFIX}|probe_xmas|XMAS scan detected",
                "detail": {"marker": TEST_MARKER_PREFIX, "probe_type": "XMAS"},
            },
            # Probe - NULL
            {
                "timestamp": ts + timedelta(minutes=16),
                "attack_type": "PROBE_NULL",
                "severity": "MEDIUM",
                "src_ip": TEST_IPS["probe_null"],
                "dst_ip": DST_IP_SERVER,
                "dst_port": 445,
                "proto": "TCP",
                "description": f"{TEST_MARKER_PREFIX}|probe_null|NULL scan detected",
                "detail": {"marker": TEST_MARKER_PREFIX, "probe_type": "NULL"},
            },
            # Probe - FIN
            {
                "timestamp": ts + timedelta(minutes=17),
                "attack_type": "PROBE_FIN",
                "severity": "MEDIUM",
                "src_ip": TEST_IPS["probe_fin"],
                "dst_ip": DST_IP_SERVER,
                "dst_port": 80,
                "proto": "TCP",
                "description": f"{TEST_MARKER_PREFIX}|probe_fin|FIN scan detected",
                "detail": {"marker": TEST_MARKER_PREFIX, "probe_type": "FIN"},
            },
            # Volume anomaly
            {
                "timestamp": ts + timedelta(minutes=20),
                "attack_type": "VOLUME_ANOMALY",
                "severity": "HIGH",
                "src_ip": TEST_IPS["high_volume"],
                "dst_ip": DST_IP_SERVER,
                "dst_port": None,
                "proto": "TCP",
                "description": f"{TEST_MARKER_PREFIX}|volume_anomaly|500 events in 1h window (baseline: 50)",
                "detail": {"marker": TEST_MARKER_PREFIX, "actual": 500, "baseline": 50, "zscore": 4.5},
            },
            # IDS signature
            {
                "timestamp": ts + timedelta(minutes=25),
                "attack_type": "IDS_ALERT",
                "severity": "CRITICAL",
                "src_ip": TEST_IPS["ids_trigger"],
                "dst_ip": DST_IP_SERVER,
                "dst_port": 3306,
                "proto": "TCP",
                "description": f"{TEST_MARKER_PREFIX}|ids_alert|ET EXPLOIT Buffer Overflow Attempt on port 3306",
                "detail": {"marker": TEST_MARKER_PREFIX, "signature": "ET EXPLOIT Buffer Overflow", "sid": 2001234},
            },
            # ZenArmor
            {
                "timestamp": ts + timedelta(minutes=30),
                "attack_type": "ZENARMOR_THREAT",
                "severity": "HIGH",
                "src_ip": TEST_IPS["zenarmor"],
                "dst_ip": DST_IP_LAN,
                "dst_port": 443,
                "proto": "TCP",
                "description": f"{TEST_MARKER_PREFIX}|zenarmor|Malware download blocked",
                "detail": {"marker": TEST_MARKER_PREFIX, "policy": "block_malware", "threat": "trojan.generic"},
            },
            # Nginx web attack
            {
                "timestamp": ts + timedelta(minutes=35),
                "attack_type": "WEB_ATTACK",
                "severity": "HIGH",
                "src_ip": TEST_IPS["nginx_web"],
                "dst_ip": DST_IP_SERVER,
                "dst_port": 443,
                "proto": "TCP",
                "description": f"{TEST_MARKER_PREFIX}|web_attack|Path traversal attempt: /../../../etc/passwd",
                "detail": {"marker": TEST_MARKER_PREFIX, "path": "/../../../etc/passwd", "attack": "path_traversal"},
            },
        ]
        return anomalies

    # ------------------------------------------------------------------
    # Baseline / drift / threat profile factories
    # ------------------------------------------------------------------
    def _make_baselines(self, hours_ago: float = 1.0) -> List[Tuple]:
        """Generate test baselines."""
        ts = datetime.now(timezone.utc) - timedelta(hours=hours_ago)
        return [
            ("TEST_SEED|events_per_hour", ts, 50.0, 10.0, 100),
            ("TEST_SEED|blocked_per_hour", ts, 5.0, 2.0, 100),
            ("TEST_SEED|unique_ips_per_hour", ts, 20.0, 5.0, 100),
            ("TEST_SEED|syn_rate", ts, 0.3, 0.1, 100),
            ("TEST_SEED|avg_packet_size", ts, 512.0, 128.0, 100),
        ]

    def _make_drift_events(self, hours_ago: float = 0.5) -> List[Tuple]:
        """Generate concept drift events."""
        ts = datetime.now(timezone.utc) - timedelta(hours=hours_ago)
        return [
            ("TEST_SEED|events_per_hour", "global", 50.0, 150.0, 2.0, 100,
             "HIGH", f"{TEST_MARKER_PREFIX}|drift|Event rate tripled in last 2 hours", ts),
            ("TEST_SEED|blocked_per_hour", "rule:TEST_SEED_RULE_BLOCK_WAN", 5.0, 50.0, 4.0, 50,
             "CRITICAL", f"{TEST_MARKER_PREFIX}|drift|Block rate spiked 10x on WAN rule", ts + timedelta(minutes=30)),
        ]

    def _make_threat_profiles(self, hours_ago: float = 1.0) -> List[Dict[str, Any]]:
        """Generate IP threat profiles for test IPs."""
        ts = datetime.now(timezone.utc) - timedelta(hours=hours_ago)
        profiles = []
        for label, ip in TEST_IPS.items():
            if label in ("port_scan", "syn_flood", "brute_force_ssh"):
                score = 85.0
            elif label in ("probe_xmas", "probe_null", "probe_fin"):
                score = 60.0
            elif label == "high_volume":
                score = 45.0
            else:
                score = 5.0
            profiles.append({
                "ip": ip,
                "unified_score": score,
                "total_events": 100 if score > 50 else 10,
                "firewall_events": 80 if score > 50 else 8,
                "first_seen": ts,
                "last_seen": datetime.now(timezone.utc),
                "geo_info": json.dumps({"marker": TEST_MARKER_PREFIX, "country": "TEST", "label": label}),
            })
        return profiles

    def _make_rule_feedback(self, hours_ago: float = 1.0) -> List[Tuple]:
        """Generate rule feedback entries."""
        ts = datetime.now(timezone.utc) - timedelta(hours=hours_ago)
        return [
            (TEST_RULES[1], ts, "ABUSIVE", f"{TEST_MARKER_PREFIX}|WAN block rule correctly classified", "test_user"),
            (TEST_RULES[2], ts + timedelta(minutes=5), "GOOD", f"{TEST_MARKER_PREFIX}|SSH block rule is legitimate", "test_user"),
            (TEST_RULES[0], ts + timedelta(minutes=10), "GOOD", f"{TEST_MARKER_PREFIX}|LAN allow rule is expected", "test_user"),
        ]

    def _make_rule_baselines(self, hours_ago: float = 1.0) -> List[Tuple]:
        """Generate rule baseline entries."""
        return [
            (TEST_RULES[0], TEST_RULES[0], DST_IP_LAN, 12, 50.0, 10.0, 80, 20,
             json.dumps({"TCP": 0.7, "UDP": 0.3}), 5.0, 10.0, 3.0, 0.8, 0.2,
             json.dumps([5, 10, 20, 40, 50, 60, 55, 45, 30, 20, 15, 10, 8, 6, 5, 5, 6, 10, 20, 35, 45, 48, 50, 52]),
             100, 3.0, 2.0, 50.0, 0.2, 0.9, True, None, None),
            (TEST_RULES[1], TEST_RULES[1], DST_IP_SERVER, 8, 200.0, 50.0, 500, 50,
             json.dumps({"TCP": 0.9, "UDP": 0.1}), 15.0, 20.0, 10.0, 0.2, 0.8,
             json.dumps([20, 50, 100, 150, 200, 250, 300, 280, 250, 200, 180, 150, 120, 100, 80, 60, 50, 80, 120, 180, 220, 250, 280, 300]),
             200, 15.0, 10.0, 200.0, 0.8, 0.85, True, None, None),
        ]

    # ------------------------------------------------------------------
    # DB helpers
    # ------------------------------------------------------------------
    def _connect(self):
        import psycopg2
        return psycopg2.connect(
            host=self.host, port=self.port, dbname=self.database,
            user=self.user, password=self.password
        )

    def _cursor(self):
        import psycopg2
        conn = self._connect()
        conn.autocommit = True
        return conn.cursor()

    def _bulk_insert_events(self, events: List[Tuple]) -> int:
        """Insert events in bulk, track IDs via returning query."""
        if not events:
            return 0
        import psycopg2
        import psycopg2.extras
        conn = self._connect()
        conn.autocommit = True
        cur = conn.cursor()
        try:
            psycopg2.extras.execute_values(
                cur,
                """INSERT INTO events
                   (timestamp, src_ip, dst_ip, src_hostname, dst_hostname,
                    src_port, dst_port, proto, action, interface,
                    direction, version, ip_ttl, ip_total_length, tcp_flags,
                    tcp_seq, tcp_ack, tcp_window, tcp_options,
                    udp_datalen, icmp_datalen, raw_message, rule_name, log_type)
                   VALUES %s""",
                events, page_size=500
            )
            count = cur.rowcount
            self._inserted_event_ids.extend(range(count))
            return count
        finally:
            cur.close()
            conn.close()

    def _bulk_insert_anomalies(self, anomalies: List[Dict[str, Any]]) -> int:
        """Insert anomalies, track returned IDs."""
        if not anomalies:
            return 0
        conn = self._connect()
        conn.autocommit = True
        cur = conn.cursor()
        try:
            inserted = 0
            for a in anomalies:
                detail = a.pop("detail", None)
                cur.execute(
                    """INSERT INTO anomalies
                       (timestamp, attack_type, severity,
                        src_ip, dst_ip, dst_port, proto,
                        description, detail)
                       VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                       RETURNING id""",
                    (
                        a.get("timestamp"),
                        a.get("attack_type"),
                        a.get("severity"),
                        a.get("src_ip"),
                        a.get("dst_ip"),
                        a.get("dst_port"),
                        a.get("proto"),
                        a.get("description"),
                        json.dumps(detail) if detail else None,
                    )
                )
                aid = cur.fetchone()[0]
                self._inserted_anomaly_ids.append(aid)
                inserted += 1
            return inserted
        finally:
            cur.close()
            conn.close()

    # ------------------------------------------------------------------
    # Seed orchestrators
    # ------------------------------------------------------------------
    def _seed_events(self, hours_ago: float) -> int:
        all_events: List[Tuple] = []
        all_events.extend(self._make_normal_traffic(100, hours_ago))
        all_events.extend(self._make_port_scan(hours_ago=hours_ago))
        all_events.extend(self._make_syn_flood(count=50, hours_ago=hours_ago * 0.5))
        all_events.extend(self._make_brute_force(count=20, hours_ago=hours_ago * 0.3))
        all_events.extend(self._make_high_volume(200, hours_ago))
        all_events.extend(self._make_zenarmor_events(10, hours_ago))
        all_events.extend(self._make_ids_events(5, hours_ago * 0.5))
        all_events.extend(self._make_nginx_events(10, hours_ago))
        return self._bulk_insert_events(all_events)

    def _seed_anomalies(self, hours_ago: float) -> int:
        return self._bulk_insert_anomalies(self._make_anomalies(hours_ago))

    def _seed_baselines(self, hours_ago: float) -> int:
        baselines = self._make_baselines(hours_ago)
        with self._cursor() as cur:
            cur.execute(
                """INSERT INTO baselines (metric, time_window, mean_value, stddev, sample_count)
                   VALUES %s
                   ON CONFLICT (metric, time_window) DO UPDATE SET
                     mean_value = EXCLUDED.mean_value,
                     stddev = EXCLUDED.stddev,
                     sample_count = EXCLUDED.sample_count,
                     updated_at = NOW()""",
            )
            # Use execute_values for bulk
            import psycopg2.extras
            psycopg2.extras.execute_values(
                cur,
                """INSERT INTO baselines (metric, time_window, mean_value, stddev, sample_count)
                   VALUES %s
                   ON CONFLICT (metric, time_window) DO UPDATE SET
                     mean_value = EXCLUDED.mean_value,
                     stddev = EXCLUDED.stddev,
                     sample_count = EXCLUDED.sample_count,
                     updated_at = NOW()""",
                baselines, page_size=50
            )
            return cur.rowcount

    def _seed_drift_events(self, hours_ago: float) -> int:
        drifts = self._make_drift_events(hours_ago)
        with self._cursor() as cur:
            count = 0
            for d in drifts:
                cur.execute(
                    """INSERT INTO drift_events
                       (metric, scope, old_mean, new_mean, drift_magnitude, window_size,
                        severity, description, timestamp)
                       VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                    d
                )
                count += 1
            return count

    def _seed_threat_profiles(self, hours_ago: float) -> int:
        profiles = self._make_threat_profiles(hours_ago)
        count = 0
        with self._cursor() as cur:
            for p in profiles:
                cur.execute(
                    """INSERT INTO ip_threat_profiles
                       (ip, unified_score, total_events, firewall_events,
                        first_seen, last_seen, geo_info)
                       VALUES (%s, %s, %s, %s, %s, %s, %s)
                       ON CONFLICT (ip) DO UPDATE SET
                         unified_score = EXCLUDED.unified_score,
                         total_events = EXCLUDED.total_events,
                         firewall_events = EXCLUDED.firewall_events,
                         last_seen = EXCLUDED.last_seen,
                         geo_info = EXCLUDED.geo_info""",
                    (p["ip"], p["unified_score"], p["total_events"], p["firewall_events"],
                     p["first_seen"], p["last_seen"], p["geo_info"])
                )
                count += 1
        return count

    def _seed_rule_feedback(self, hours_ago: float) -> int:
        feedbacks = self._make_rule_feedback(hours_ago)
        with self._cursor() as cur:
            count = 0
            for fb in feedbacks:
                cur.execute(
                    """INSERT INTO rule_feedback (rule_name, timestamp, label, reason, user_id)
                       VALUES (%s, %s, %s, %s, %s)""",
                    fb
                )
                count += 1
        return count

    def _seed_rule_baselines(self, hours_ago: float) -> int:
        baselines = self._make_rule_baselines(hours_ago)
        with self._cursor() as cur:
            count = 0
            for bl in baselines:
                cur.execute(
                    """INSERT INTO rule_baselines
                       (rule, rule_name, ip, hour,
                        avg_events_per_hour, std_events_per_hour,
                        max_events_per_hour, min_events_per_hour,
                        protocol_distribution, avg_dst_ports, avg_src_ports,
                        avg_unique_dst_ips, pass_ratio, block_ratio,
                        hourly_distribution, sample_count,
                        avg_port_diversity, avg_dest_diversity,
                        avg_volume, avg_block_ratio,
                        baseline_goodness, baseline_updated,
                        window_start, window_end)
                       VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                               %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                       ON CONFLICT DO NOTHING""",
                    bl
                )
                count += cur.rowcount
        return count


# ---------------------------------------------------------------------------
# Context manager support
# ---------------------------------------------------------------------------
class _SeederContext:
    """Context manager: seeds on enter, cleans up on exit."""
    def __init__(self, seeder: TestSeeder, seed_fn=str):
        self.seeder = seeder
        self.seed_fn = seed_fn  # 'all', 'mixed', or callable

    def __enter__(self) -> Dict[str, int]:
        if self.seed_fn == "all":
            return self.seeder.seed_all()
        elif self.seed_fn == "mixed":
            return self.seeder.seed_mixed()
        elif callable(self.seed_fn):
            return self.seed_fn(self.seeder)
        return self.seeder.seed_all()

    def __exit__(self, *exc):
        self.seeder.cleanup()
        return False


def seeded(seeder: Optional[TestSeeder] = None, mode: str = "all"):
    """Decorator/context for test functions.

    Usage:
        with seeded(mode="mixed") as counts:
            # test data is present
        # automatically cleaned up

        def test_something():
            with seeded(mode="all"):
                ...
    """
    if seeder is None:
        seeder = TestSeeder()
    return _SeederContext(seeder, mode)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Test data seeder for OPNsense Anomaly Agent")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--seed", action="store_true", help="Seed all test data")
    group.add_argument("--mixed", action="store_true", help="Seed mixed realistic traffic")
    group.add_argument("--clean", action="store_true", help="Remove all test data")
    group.add_argument("--count", action="store_true", help="Count existing test records")
    group.add_argument("--dry-run", action="store_true", help="Print what would be inserted without inserting")
    parser.add_argument("--hours-ago", type=float, default=1.0,
                        help="How far back to place events (default: 1 hour)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    seeder = TestSeeder()

    if args.dry_run:
        print("[DRY RUN] Would insert:")
        events = (seeder._make_normal_traffic(100, args.hours_ago) +
                  seeder._make_port_scan(hours_ago=args.hours_ago) +
                  seeder._make_syn_flood(count=50, hours_ago=args.hours_ago * 0.5) +
                  seeder._make_brute_force(count=20, hours_ago=args.hours_ago * 0.3) +
                  seeder._make_high_volume(200, args.hours_ago) +
                  seeder._make_zenarmor_events(10, args.hours_ago) +
                  seeder._make_ids_events(5, args.hours_ago * 0.5) +
                  seeder._make_nginx_events(10, args.hours_ago))
        print(f"  Events: {len(events)}")
        print(f"  Anomalies: {len(seeder._make_anomalies(args.hours_ago))}")
        print(f"  Baselines: {len(seeder._make_baselines(args.hours_ago))}")
        print(f"  Drift events: {len(seeder._make_drift_events(args.hours_ago))}")
        print(f"  Threat profiles: {len(seeder._make_threat_profiles(args.hours_ago))}")
        print(f"  Rule feedback: {len(seeder._make_rule_feedback(args.hours_ago))}")
        print(f"  Rule baselines: {len(seeder._make_rule_baselines(args.hours_ago))}")
        print(f"\n  Marker IP range: {MARKER_IP_BASE}.x")
        print(f"  Marker prefix: {TEST_MARKER_PREFIX}")
        print(f"\n  Test IPs:")
        for label, ip in TEST_IPS.items():
            print(f"    {ip:20s} -> {label}")
        return

    try:
        if args.clean:
            counts = seeder.cleanup()
            print(f"Cleaned: {json.dumps(counts, indent=2)}")
        elif args.count:
            counts = seeder.count_test_records()
            print(f"Test records: {json.dumps(counts, indent=2)}")
        elif args.mixed:
            counts = seeder.seed_mixed(hours_ago=args.hours_ago)
            print(f"Seeded (mixed): {json.dumps(counts, indent=2)}")
        else:
            counts = seeder.seed_all(hours_ago=args.hours_ago)
            print(f"Seeded (all): {json.dumps(counts, indent=2)}")
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
