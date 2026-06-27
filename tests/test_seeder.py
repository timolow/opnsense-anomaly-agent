"""Tests for test_data_seeder module.

Verifies that all data factories produce correctly shaped records
and that the marker IP/constants are properly applied.

These tests run against the factories only (no DB required).
"""

import sys
import os
import json
from datetime import datetime, timezone, timedelta

# Import from project root (parent of tests/)
_project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

# Remove tests/ from path to avoid self-import collision
_tests_dir = os.path.dirname(os.path.abspath(__file__))
if _tests_dir in sys.path:
    sys.path.remove(_tests_dir)

import unittest

# Force reimport from correct location
if "test_data_seeder" in sys.modules:
    del sys.modules["test_data_seeder"]

from test_data_seeder import (
    TestSeeder, TEST_IPS, MARKER_IP_BASE, TEST_MARKER_PREFIX,
    DST_IP_LAN, DST_IP_SERVER, TEST_RULES,
)

# Event tuple column indices
# 0: timestamp, 1: src_ip, 2: dst_ip, 3: src_hostname, 4: dst_hostname,
# 5: src_port, 6: dst_port, 7: proto, 8: action, 9: interface,
# 10: direction, 11: version, 12: ip_ttl, 13: ip_total_length,
# 14: tcp_flags, 15: tcp_seq, 16: tcp_ack, 17: tcp_window, 18: tcp_options,
# 19: udp_datalen, 20: icmp_datalen, 21: raw_message, 22: rule_name, 23: log_type
COL_TS = 0
COL_SRC_IP = 1
COL_DST_IP = 2
COL_SRC_HOST = 3
COL_DST_HOST = 4
COL_SRC_PORT = 5
COL_DST_PORT = 6
COL_PROTO = 7
COL_ACTION = 8
COL_IFACE = 9
COL_DIRECTION = 10
COL_VERSION = 11
COL_TTL = 12
COL_TOTAL_LEN = 13
COL_TCP_FLAGS = 14
COL_RAW_MSG = 21
COL_RULE_NAME = 22
COL_LOG_TYPE = 23
EVENT_TUPLE_LEN = 24


class TestConstants(unittest.TestCase):
    """Verify marker constants are consistent and RFC1918-safe."""

    def test_marker_ip_range(self):
        self.assertTrue(MARKER_IP_BASE.startswith("192.168."))

    def test_test_ips_use_marker_range(self):
        for label, ip in TEST_IPS.items():
            self.assertTrue(
                ip.startswith(MARKER_IP_BASE + "."),
                f"TEST_IPS[{label!r}] = {ip!r} does not start with {MARKER_IP_BASE}.",
            )

    def test_dst_ips_use_marker_range(self):
        self.assertTrue(DST_IP_LAN.startswith(MARKER_IP_BASE + "."))
        self.assertTrue(DST_IP_SERVER.startswith(MARKER_IP_BASE + "."))

    def test_test_rules_have_marker_prefix(self):
        for rule in TEST_RULES:
            self.assertTrue(
                rule.startswith(TEST_MARKER_PREFIX),
                f"Rule {rule!r} missing marker prefix.",
            )

    def test_unique_test_ips(self):
        ips = list(TEST_IPS.values())
        self.assertEqual(len(ips), len(set(ips)), "Duplicate IPs in TEST_IPS")


class TestSeederFactories(unittest.TestCase):
    """Test all factory methods produce correctly shaped data."""

    def setUp(self):
        self.seeder = TestSeeder()

    # -- Event factories --

    def test_make_normal_traffic_shape(self):
        events = self.seeder._make_normal_traffic(10, hours_ago=1.0)
        self.assertEqual(len(events), 10)
        for evt in events:
            self.assertIsInstance(evt, tuple)
            self.assertEqual(len(evt), EVENT_TUPLE_LEN)
            self.assertIsInstance(evt[COL_TS], datetime)
            self.assertTrue(evt[COL_SRC_IP].startswith(MARKER_IP_BASE))
            self.assertEqual(evt[COL_DST_IP], DST_IP_LAN)
            self.assertIn(evt[COL_PROTO], ("TCP", "UDP"))
            self.assertIn(evt[COL_ACTION], ("PASS", "BLOCK"))
            self.assertTrue(evt[COL_RAW_MSG].startswith(TEST_MARKER_PREFIX))
            self.assertIn(evt[COL_RULE_NAME], TEST_RULES)
            self.assertEqual(evt[COL_LOG_TYPE], "filterlog")

    def test_make_normal_traffic_spread_in_time(self):
        events = self.seeder._make_normal_traffic(100, hours_ago=2.0)
        timestamps = [evt[COL_TS] for evt in events]
        time_span = (timestamps[-1] - timestamps[0]).total_seconds()
        self.assertGreater(time_span, 0)

    def test_make_port_scan_shape(self):
        events = self.seeder._make_port_scan(
            src_ip=TEST_IPS["port_scan"],
            ports=[22, 80, 443],
            hours_ago=0.5,
        )
        self.assertEqual(len(events), 3)
        for evt in events:
            self.assertEqual(evt[COL_SRC_IP], TEST_IPS["port_scan"])
            self.assertEqual(evt[COL_DST_IP], DST_IP_SERVER)
            self.assertEqual(evt[COL_PROTO], "TCP")
            self.assertEqual(evt[COL_ACTION], "BLOCK")
            self.assertEqual(evt[COL_TCP_FLAGS], "SYN")

    def test_make_port_scan_default_ports(self):
        events = self.seeder._make_port_scan()
        self.assertEqual(len(events), 16)

    def test_make_port_scan_default_src_ip(self):
        events = self.seeder._make_port_scan(ports=[80])
        self.assertEqual(events[0][COL_SRC_IP], TEST_IPS["port_scan"])

    def test_make_syn_flood_shape(self):
        events = self.seeder._make_syn_flood(count=50, hours_ago=0.25)
        self.assertEqual(len(events), 50)
        for evt in events:
            self.assertEqual(evt[COL_SRC_IP], TEST_IPS["syn_flood"])
            self.assertEqual(evt[COL_DST_PORT], 80)
            self.assertEqual(evt[COL_TCP_FLAGS], "SYN")
            self.assertIn("syn_flood", evt[COL_RAW_MSG])

    def test_make_syn_flood_default_src_ip(self):
        events = self.seeder._make_syn_flood(count=5)
        self.assertEqual(events[0][COL_SRC_IP], TEST_IPS["syn_flood"])

    def test_make_brute_force_shape(self):
        events = self.seeder._make_brute_force(count=20, hours_ago=0.5)
        self.assertEqual(len(events), 20)
        for evt in events:
            self.assertEqual(evt[COL_SRC_IP], TEST_IPS["brute_force_ssh"])
            self.assertEqual(evt[COL_DST_PORT], 22)
            self.assertIn("brute_force_ssh", evt[COL_RAW_MSG])

    def test_make_brute_force_default_src_ip(self):
        events = self.seeder._make_brute_force(count=5)
        self.assertEqual(events[0][COL_SRC_IP], TEST_IPS["brute_force_ssh"])

    def test_make_high_volume_shape(self):
        events = self.seeder._make_high_volume(count=200, hours_ago=1.0)
        self.assertEqual(len(events), 200)
        for evt in events:
            self.assertEqual(evt[COL_SRC_IP], TEST_IPS["high_volume"])
            self.assertIn("high_volume", evt[COL_RAW_MSG])

    def test_make_zenarmor_events_shape(self):
        events = self.seeder._make_zenarmor_events(count=5, hours_ago=1.0)
        self.assertEqual(len(events), 5)
        for evt in events:
            self.assertEqual(evt[COL_LOG_TYPE], "zenarmor")
            self.assertIn("zenarmor", evt[COL_RAW_MSG])

    def test_make_ids_events_shape(self):
        events = self.seeder._make_ids_events(count=3, hours_ago=0.5)
        self.assertEqual(len(events), 3)
        for evt in events:
            self.assertEqual(evt[COL_LOG_TYPE], "ids")
            self.assertIn("ids", evt[COL_RAW_MSG])

    def test_make_nginx_events_shape(self):
        events = self.seeder._make_nginx_events(count=5, hours_ago=1.0)
        self.assertEqual(len(events), 5)
        for evt in events:
            self.assertEqual(evt[COL_LOG_TYPE], "nginx")
            self.assertIn("nginx", evt[COL_RAW_MSG])

    # -- Anomaly factories --

    def test_make_anomalies_covers_all_types(self):
        anomalies = self.seeder._make_anomalies(hours_ago=0.5)
        attack_types = {a["attack_type"] for a in anomalies}
        expected_types = {
            "PORT_SCAN", "SYN_FLOOD", "BRUTE_FORCE",
            "PROBE_XMAS", "PROBE_NULL", "PROBE_FIN",
            "VOLUME_ANOMALY", "IDS_ALERT", "ZENARMOR_THREAT", "WEB_ATTACK",
        }
        self.assertEqual(attack_types, expected_types,
                         f"Missing attack types: {expected_types - attack_types}")

    def test_make_anomalies_has_marker(self):
        anomalies = self.seeder._make_anomalies()
        for a in anomalies:
            self.assertTrue(
                a["description"].startswith(TEST_MARKER_PREFIX),
                f"Anomaly {a['attack_type']} missing marker in description",
            )
            self.assertIn("detail", a)
            self.assertEqual(a["detail"]["marker"], TEST_MARKER_PREFIX)
            self.assertTrue(a["src_ip"].startswith(MARKER_IP_BASE))
            self.assertIn(a["severity"], ("CRITICAL", "HIGH", "MEDIUM", "LOW"))

    def test_make_anomalies_timestamps(self):
        anomalies = self.seeder._make_anomalies(hours_ago=1.0)
        for a in anomalies:
            self.assertIsInstance(a["timestamp"], datetime)
            self.assertIsNotNone(a["timestamp"].tzinfo)

    # -- Baseline / drift / threat profile factories --

    def test_make_baselines_shape(self):
        baselines = self.seeder._make_baselines()
        self.assertEqual(len(baselines), 5)
        for bl in baselines:
            self.assertEqual(len(bl), 5)
            self.assertTrue(bl[0].startswith(TEST_MARKER_PREFIX))
            self.assertIsInstance(bl[1], datetime)
            self.assertIsInstance(bl[2], float)
            self.assertIsInstance(bl[3], float)
            self.assertIsInstance(bl[4], int)

    def test_make_drift_events_shape(self):
        drifts = self.seeder._make_drift_events()
        self.assertEqual(len(drifts), 2)
        for d in drifts:
            self.assertEqual(len(d), 9)
            self.assertTrue(d[0].startswith(TEST_MARKER_PREFIX))
            self.assertIn(d[6], ("HIGH", "CRITICAL"))

    def test_make_threat_profiles_shape(self):
        profiles = self.seeder._make_threat_profiles()
        self.assertEqual(len(profiles), len(TEST_IPS))
        for p in profiles:
            self.assertIn("ip", p)
            self.assertTrue(p["ip"].startswith(MARKER_IP_BASE))
            self.assertIn("unified_score", p)
            self.assertIsInstance(p["unified_score"], float)
            geo = json.loads(p["geo_info"])
            self.assertEqual(geo["marker"], TEST_MARKER_PREFIX)

    def test_threat_profiles_score_tiers(self):
        profiles = self.seeder._make_threat_profiles()
        by_ip = {p["ip"]: p for p in profiles}
        self.assertGreater(by_ip[TEST_IPS["port_scan"]]["unified_score"], 70)
        self.assertLess(by_ip[TEST_IPS["normal_tcp"]]["unified_score"], 20)

    def test_make_rule_feedback_shape(self):
        feedbacks = self.seeder._make_rule_feedback()
        self.assertEqual(len(feedbacks), 3)
        for fb in feedbacks:
            self.assertEqual(len(fb), 5)
            self.assertIn(fb[0], TEST_RULES)
            self.assertIn(fb[2], ("GOOD", "ABUSIVE"))

    def test_make_rule_baselines_shape(self):
        baselines = self.seeder._make_rule_baselines()
        self.assertEqual(len(baselines), 2)
        for bl in baselines:
            self.assertEqual(len(bl), 24)
            self.assertIn(bl[0], TEST_RULES)


class TestSeederAPI(unittest.TestCase):
    """Test the public API methods that don't require DB."""

    def setUp(self):
        self.seeder = TestSeeder()

    def test_seed_normal_traffic_delegates(self):
        events = self.seeder._make_normal_traffic(25, hours_ago=1.0)
        self.assertEqual(len(events), 25)

    def test_seed_port_scan_delegates(self):
        events = self.seeder._make_port_scan(ports=[80, 443, 8080])
        self.assertEqual(len(events), 3)

    def test_seed_syn_flood_delegates(self):
        events = self.seeder._make_syn_flood(count=75)
        self.assertEqual(len(events), 75)

    def test_seed_brute_force_delegates(self):
        events = self.seeder._make_brute_force(count=15)
        self.assertEqual(len(events), 15)

    def test_seed_high_volume_delegates(self):
        events = self.seeder._make_high_volume(count=1000)
        self.assertEqual(len(events), 1000)


if __name__ == "__main__":
    unittest.main()
