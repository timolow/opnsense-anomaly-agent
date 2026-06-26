"""Integration tests using realistic sample syslog events.

These tests replay actual OPNsense syslog event patterns against the
full detection pipeline (adaptive_parser -> attack_detectors -> discord embeds)
to verify no regressions in field names, port data, or detection logic.
"""

import sys
import os
import time
from datetime import datetime, timezone, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from attack_detectors import AttackDetector
from discord_bot import generate_attack_embed


# ── Realistic sample events from OPNsense syslog ─────────────────────────

# BRUTE_FORCE pattern: repeated SSH blocking
def make_ssh_brute_events(src_ip, count=10):
    events = []
    for i in range(count):
        ts = (datetime.now(timezone.utc) - timedelta(seconds=count - i)).isoformat()
        events.append({
            'src_ip': src_ip,
            'dst_ip': '192.168.1.1',
            'dport': 22,
            'sport': 49152 + i,
            'proto': 'TCP',
            'action': 'BLOCK',
            'tcp_flags': 'SYN',
            'timestamp': ts,
            'description': f'SSH authentication failure from {src_ip} on port 22',
        })
    return events


def make_port_scan_events(src_ip, ports=None):
    if ports is None:
        ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 3389, 5432, 8080, 8443]
    events = []
    for i, port in enumerate(ports):
        ts = (datetime.now(timezone.utc) - timedelta(seconds=len(ports) - i)).isoformat()
        events.append({
            'src_ip': src_ip,
            'dst_ip': '192.168.1.1',
            'dport': port,
            'sport': 50000 + i,
            'proto': 'TCP',
            'action': 'BLOCK',
            'tcp_flags': 'SYN',
            'timestamp': ts,
        })
    return events


def make_syn_flood_events(src_ip, count=10):
    events = []
    for i in range(count):
        ts = (datetime.now(timezone.utc) - timedelta(seconds=count - i)).isoformat()
        events.append({
            'src_ip': src_ip,
            'dst_ip': '192.168.1.1',
            'dport': 80,
            'sport': 60000 + i,
            'proto': 'TCP',
            'action': 'BLOCK',
            'tcp_flags': 'SYN',
            'timestamp': ts,
        })
    return events


def make_probe_events(src_ip, probe_type='XMAS', port=445):
    """Probe type: XMAS, NULL, FIN, or ICMP_FLOOD."""
    ts = datetime.now(timezone.utc).isoformat()
    if probe_type == 'ICMP_FLOOD':
        return [{
            'src_ip': src_ip,
            'dst_ip': '192.168.1.1',
            'dport': 0,
            'sport': 0,
            'proto': 'ICMP',
            'action': 'BLOCK',
            'timestamp': ts,
            'description': f'ICMP flood from {src_ip}',
        }] * 6
    else:
        return [{
            'src_ip': src_ip,
            'dst_ip': '192.168.1.1',
            'dport': port,
            'sport': 55000,
            'proto': 'TCP',
            'action': 'BLOCK',
            'tcp_flags': probe_type,
            'timestamp': ts,
        }]


# ── Integration test: full pipeline ──────────────────────────────────────

class TestIntegration:
    """End-to-end tests: syslog -> parser -> detector -> embed."""

    def test_full_brute_force_pipeline(self):
        """Replay SSH brute force: syslog events -> detection -> embed with port."""
        ad = AttackDetector(
            dedup_seconds=300,
            config={
                'port_scan_vertical': 2,
                'port_scan_window': 120,
                'brute_force_threshold': 5,
                'brute_force_window': 60,
                'syn_flood_threshold': 5,
                'syn_flood_window': 30,
                'probe_threshold': 1,
                'probe_window': 30,
            },
        )

        events = make_ssh_brute_events('45.33.32.156', count=8)
        all_results = []
        for ev in events:
            results = ad.check_event(ev)
            if results:
                all_results.extend(results)

        # Should have detected at least one brute force
        bf_results = [r for r in all_results if r['attack_type'] == 'BRUTE_FORCE']
        assert len(bf_results) >= 1, "SSH brute force should be detected"

        # Verify port is present in detection output
        assert bf_results[0]['dst_port'] == 22, "Port must be 22 (SSH)"

        # Verify service name is computed
        assert bf_results[0]['detail']['service'] == 'SSH'

        # Generate embed and verify port appears in fields
        embed = generate_attack_embed(bf_results[0])
        service_field = next(
            (f for f in embed.fields if f['name'] == 'Service'),
            None
        )
        assert service_field is not None, "Service field must exist in embed"
        assert '22' in service_field['value'], f"Port must appear in Service field: {service_field['value']}"

    def test_full_port_scan_pipeline(self):
        """Replay port scan: many ports from one source -> detection -> embed."""
        ad = AttackDetector(
            dedup_seconds=300,
            config={
                'port_scan_vertical': 5,
                'port_scan_window': 120,
                'brute_force_threshold': 100,
                'brute_force_window': 60,
                'syn_flood_threshold': 100,
                'syn_flood_window': 30,
                'probe_threshold': 100,
                'probe_window': 30,
            },
        )

        events = make_port_scan_events('103.235.46.39', ports=[22, 80, 443, 3389, 8080])
        all_results = []
        for ev in events:
            results = ad.check_event(ev)
            if results:
                all_results.extend(results)

        ps_results = [r for r in all_results if r['attack_type'] == 'PORT_SCAN']
        assert len(ps_results) >= 1, "Port scan should be detected"

        # Verify port_list contains the scanned ports
        port_list = ps_results[0]['detail']['port_list']
        assert len(port_list) >= 5, f"port_list should have 5+ ports, got {len(port_list)}"

        # Generate embed and verify ports appear
        embed = generate_attack_embed(ps_results[0])
        ports_field = next(
            (f for f in embed.fields if f['name'] == 'Scanned Ports'),
            None,
        )
        assert ports_field is not None, "Scanned Ports field must exist"
        assert '22' in ports_field['value'], "Port 22 must appear in Scanned Ports"
        assert '443' in ports_field['value'], "Port 443 must appear in Scanned Ports"

    def test_full_syn_flood_pipeline(self):
        """Replay SYN flood: many SYN packets to same port -> detection."""
        ad = AttackDetector(
            dedup_seconds=300,
            config={
                'port_scan_vertical': 100,
                'port_scan_window': 120,
                'brute_force_threshold': 100,
                'brute_force_window': 60,
                'syn_flood_threshold': 5,
                'syn_flood_window': 30,
                'probe_threshold': 100,
                'probe_window': 30,
            },
        )

        events = make_syn_flood_events('185.220.101.1', count=8)
        all_results = []
        for ev in events:
            results = ad.check_event(ev)
            if results:
                all_results.extend(results)

        syn_results = [r for r in all_results if r['attack_type'] == 'SYN_FLOOD']
        assert len(syn_results) >= 1, "SYN flood should be detected"

        # Verify port is in detection output
        assert syn_results[0]['dst_port'] == 80, "SYN flood port must be 80"

        # Generate embed and verify port appears
        embed = generate_attack_embed(syn_results[0])
        port_field = next(
            (f for f in embed.fields if f['name'] == 'Port'),
            None,
        )
        assert port_field is not None, "Port field must exist in SYN_FLOOD embed"
        assert '80' in port_field['value'], f"Port must be 80: {port_field['value']}"

    def test_full_probe_pipeline(self):
        """Replay XMAS scan probe -> detection -> embed with signature."""
        ad = AttackDetector(
            dedup_seconds=300,
            config={
                'port_scan_vertical': 100,
                'port_scan_window': 120,
                'brute_force_threshold': 100,
                'brute_force_window': 60,
                'syn_flood_threshold': 100,
                'syn_flood_window': 30,
                'probe_threshold': 1,
                'probe_window': 30,
            },
        )

        events = make_probe_events('91.240.118.172', probe_type='XMAS', port=445)
        all_results = []
        for ev in events:
            results = ad.check_event(ev)
            if results:
                all_results.extend(results)

        probe_results = [r for r in all_results if r['attack_type'] == 'PROBE']
        assert len(probe_results) >= 1, "XMAS scan probe should be detected"

        # Verify port is in detection output
        assert probe_results[0]['dst_port'] == 445

        # Verify flags field (not 'signature')
        assert 'flags' in probe_results[0]['detail']

        # Generate embed and verify signature field exists with flags data
        embed = generate_attack_embed(probe_results[0])
        sig_field = next(
            (f for f in embed.fields if f['name'] == 'Signature'),
            None,
        )
        assert sig_field is not None, "Signature field must exist"
        assert 'N/A' not in sig_field['value'], "Signature should not be N/A"

    def test_window_expiration_integration(self):
        """Verify old events are cleaned up when window expires.

        Send 1 old event (below threshold), then current event.
        If old events are properly expired, count should stay at 1
        (only current event), not 2, so no brute force fires.
        If old events are NOT expired (regression), count=2 and
        brute force incorrectly fires.
        """
        ad = AttackDetector(
            dedup_seconds=300,
            config={
                'port_scan_vertical': 100, 'port_scan_window': 120,
                'brute_force_threshold': 2, 'brute_force_window': 1,
                'syn_flood_threshold': 100, 'syn_flood_window': 30,
                'probe_threshold': 100, 'probe_window': 30,
            },
        )

        # Send 1 old event (count=1, below threshold=2)
        old_ev = {
            'src_ip': '10.0.0.1', 'dst_ip': '192.168.1.1', 'dport': 22,
            'proto': 'TCP', 'action': 'BLOCK',
            'timestamp': (datetime.now(timezone.utc) - timedelta(seconds=10)).isoformat(),
        }
        r1 = ad.check_event(old_ev)
        # count=1, no detection

        # Send 1 current event
        current_ev = {
            'src_ip': '10.0.0.1', 'dst_ip': '192.168.1.1', 'dport': 22,
            'proto': 'TCP', 'action': 'BLOCK',
            'timestamp': datetime.now(timezone.utc).isoformat(),
        }
        r2 = ad.check_event(current_ev)
        # If old events expired: count=1 (current only), no detection
        # If old events NOT expired (regression): count=2, detection fires

        bf_results = [r for r in (r1 or []) + (r2 or [])
                      if r['attack_type'] == 'BRUTE_FORCE']

        assert len(bf_results) == 0, (
            f"Old events should be expired after 10s gap (window=1s). "
            f"Got {len(bf_results)} brute force results. "
            f"Old events were NOT cleaned up — _parse_ts regression!"
        )


    def test_different_protocols_not_deduped(self):
        """ICMP probe and TCP XMAS probe should trigger independently."""
        ad = AttackDetector(
            dedup_seconds=0,  # No dedup
            config={
                'port_scan_vertical': 100,
                'port_scan_window': 120,
                'brute_force_threshold': 100,
                'brute_force_window': 60,
                'syn_flood_threshold': 100,
                'syn_flood_window': 30,
                'probe_threshold': 1,
                'probe_window': 30,
            },
        )

        tcp_probe = make_probe_events('10.0.0.1', probe_type='XMAS')[0]
        icmp_probe = make_probe_events('10.0.0.2', probe_type='ICMP_FLOOD')[0]

        results = ad.check_event(tcp_probe) + ad.check_event(icmp_probe)

        assert len(results) >= 2, "Both XMAS and ICMP probes should trigger"
        types = set(r['attack_type'] for r in results)
        assert 'PROBE' in types


class TestEmbedStructureRegression:
    """Verify embed structure hasn't broken for any attack type."""

    def test_all_embed_types_have_required_fields(self):
        """Every attack type embed must have: Severity, timestamp, fields."""
        for attack_type, attack in self._sample_attacks().items():
            embed = generate_attack_embed(attack)
            assert embed.title != '', f"{attack_type}: title must not be empty"
            assert len(embed.fields) > 0, f"{attack_type}: must have at least one field"
            for f in embed.fields:
                assert 'name' in f, f"{attack_type}: field must have 'name'"
                assert 'value' in f, f"{attack_type}: field must have 'value'"

    def _sample_attacks(self):
        return {
            'BRUTE_FORCE': {
                'attack_type': 'BRUTE_FORCE',
                'severity': 'HIGH',
                'src_ip': '45.33.32.156',
                'dst_ip': '192.168.1.1',
                'dst_port': 22,
                'proto': 'TCP',
                'detail': {
                    'attempt_count': 50,
                    'threshold': 5,
                    'service': 'SSH',
                    'window_seconds': 60,
                },
                'description': 'Brute force detected: 50 attempts in 60s',
            },
            'PORT_SCAN': {
                'attack_type': 'PORT_SCAN',
                'severity': 'HIGH',
                'src_ip': '103.235.46.39',
                'dst_ip': '192.168.1.1',
                'dst_port': 80,
                'proto': 'TCP',
                'scan_subtype': 'VERTICAL',
                'detail': {
                    'distinct_ports': 16,
                    'port_list': [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 3389, 5432, 8080, 8443],
                    'threshold': 5,
                },
                'description': 'Port scan detected',
            },
            'SYN_FLOOD': {
                'attack_type': 'SYN_FLOOD',
                'severity': 'CRITICAL',
                'src_ip': '185.220.101.1',
                'dst_ip': '192.168.1.1',
                'dst_port': 80,
                'proto': 'TCP',
                'detail': {
                    'syn_count': 100,
                    'threshold': 5,
                    'window_seconds': 30,
                    'top_sources': ['185.220.101.1'],
                },
                'description': 'SYN flood detected',
            },
            'PROBE': {
                'attack_type': 'PROBE',
                'severity': 'MEDIUM',
                'src_ip': '91.240.118.172',
                'dst_ip': '192.168.1.1',
                'dst_port': 445,
                'proto': 'TCP',
                'scan_subtype': 'XMAS_SCAN',
                'detail': {
                    'flags': 'XMAS (FIN+PSH+URG)',
                },
                'description': 'Probe detected',
            },
        }
