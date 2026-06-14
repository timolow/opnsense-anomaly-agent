"""
Attack detectors for OPNsense anomaly detection agent.

Monitors event streams to detect common attack patterns:
- Port scans (horizontal & vertical)
- SYN floods
- Brute force attempts
- Network probes / service enumeration
- XMAS / NULL / FIN scans
"""

import time
import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, List, Set, Tuple
from collections import defaultdict

logger = logging.getLogger(__name__)


# ============================================================
# Attack detection engines
# ============================================================


class PortScanDetector:
    """Detects port scans: rapid connections to many ports or many hosts from a single source.
    
    Configurable thresholds:
    - vertical_threshold: max distinct dst_ports per src_ip in window before flagging
    - horizontal_threshold: max distinct dst_ips per src_ip in window before flagging
    - window_seconds: time window for counting
    """
    
    def __init__(self, vertical_threshold: int = 15, horizontal_threshold: int = 10, window_seconds: int = 120):
        self.vertical_threshold = vertical_threshold
        self.horizontal_threshold = horizontal_threshold
        self.window_seconds = window_seconds
        
        # Track: src_ip -> list of (timestamp, dst_ip, dst_port)
        self._events: Dict[str, List[Tuple[datetime, str, Optional[int]]]] = defaultdict(list)
    
    @staticmethod
    def _parse_ts(ts_raw) -> datetime:
        """Parse a timestamp from an event (string or datetime)."""
        if isinstance(ts_raw, datetime):
            return ts_raw
        if isinstance(ts_raw, str):
            # Handle ISO format with optional microseconds
            for fmt in (
                '%Y-%m-%dT%H:%M:%S.%f%z',  # with microseconds + tz
                '%Y-%m-%dT%H:%M:%S%z',     # no microseconds + tz
                '%Y-%m-%dT%H:%M:%S.%f',    # with microseconds, no tz
                '%Y-%m-%dT%H:%M:%SZ',      # UTC suffix
                '%Y-%m-%dT%H:%M:%S',       # no tz
                '%Y-%m-%d %H:%M:%S.%f',    # space-separated + us
                '%Y-%m-%d %H:%M:%S',       # space-separated
            ):
                try:
                    dt = datetime.strptime(ts_raw, fmt)
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    return dt
                except ValueError:
                    continue
        return datetime.now(timezone.utc)
    
    def _cleanup(self, src_ip: str, now: datetime):
        """Remove events older than window."""
        cutoff = now - timedelta(seconds=self.window_seconds)
        self._events[src_ip] = [
            (t, d, p) for t, d, p in self._events[src_ip] if t >= cutoff
        ]

    def check(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Check if this event is part of a port scan."""
        src_ip = event.get('src_ip')
        dst_ip = event.get('dst_ip')
        dst_port = event.get('dport')
        ts = self._parse_ts(event.get('timestamp'))
        action = event.get('action', '')
        
        # Only check BLOCKED events to reduce noise
        if action != 'BLOCK':
            return None
        
        if not src_ip or not dst_ip:
            return None
        
        self._cleanup(src_ip, ts)
        self._events[src_ip].append((ts, dst_ip, dst_port))
        
        # Check vertical scan: many distinct ports from this source
        dst_ports = set(p for _, _, p in self._events[src_ip] if p is not None)
        if len(dst_ports) >= self.vertical_threshold:
            return {
                'attack_type': 'PORT_SCAN',
                'scan_subtype': 'VERTICAL',
                'severity': 'HIGH',
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'dst_port': dst_port,
                'proto': event.get('proto', 'UNKNOWN'),
                'description': f"Port scan detected: {src_ip} hit {len(dst_ports)} distinct ports in {self.window_seconds}s",
                'detail': {
                    'distinct_ports': len(dst_ports),
                    'port_list': sorted(dst_ports)[:50],  # top 50 ports
                    'threshold': self.vertical_threshold,
                },
            }
        
        # Check horizontal scan: hitting many distinct hosts
        dst_hosts = set(d for _, d, _ in self._events[src_ip])
        if len(dst_hosts) >= self.horizontal_threshold:
            return {
                'attack_type': 'PORT_SCAN',
                'scan_subtype': 'HORIZONTAL',
                'severity': 'HIGH',
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'dst_port': dst_port,
                'proto': event.get('proto', 'UNKNOWN'),
                'description': f"Horizontal scan detected: {src_ip} contacted {len(dst_hosts)} hosts in {self.window_seconds}s",
                'detail': {
                    'distinct_hosts': len(dst_hosts),
                    'host_list': sorted(dst_hosts)[:30],
                    'threshold': self.horizontal_threshold,
                },
            }
        
        return None


class SYNFloodDetector:
    """Detects SYN floods: high rate of SYN packets from a single source or to a single destination.
    
    Configurable thresholds:
    - syn_threshold: max SYN packets in window before flagging
    - window_seconds: time window for counting
    """
    
    def __init__(self, syn_threshold: int = 30, window_seconds: int = 30):
        self.syn_threshold = syn_threshold
        self.window_seconds = window_seconds
        
        # Track: dst_ip -> list of (timestamp, src_ip)
        self._dst_events: Dict[str, List[Tuple[datetime, str]]] = defaultdict(list)
        
        # Track: src_ip -> list of timestamps
        self._src_events: List[Tuple[datetime, str]] = []
    
    @staticmethod
    def _parse_ts(ts_raw) -> datetime:
        if isinstance(ts_raw, datetime):
            return ts_raw
        if isinstance(ts_raw, str):
            for fmt in (
                '%Y-%m-%dT%H:%M:%S.%f%z',
                '%Y-%m-%dT%H:%M:%S%z', '%Y-%m-%dT%H:%M:%S.%f',
                '%Y-%m-%dT%H:%M:%SZ', '%Y-%m-%dT%H:%M:%S',
                '%Y-%m-%d %H:%M:%S.%f', '%Y-%m-%d %H:%M:%S',
            ):
                try:
                    dt = datetime.strptime(ts_raw, fmt)
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    return dt
                except ValueError:
                    continue
        return datetime.now(timezone.utc)
    
    def _cleanup(self, now: datetime):
        cutoff = now - timedelta(seconds=self.window_seconds)
        for k in self._dst_events:
            self._dst_events[k] = [
                (t, s) for t, s in self._dst_events[k] if t >= cutoff
            ]
        self._src_events = [(t, s) for t, s in self._src_events if t >= cutoff]
    
    def check(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Check if this event is part of a SYN flood."""
        tcp_flags = event.get('tcp_flags', '')
        if tcp_flags != 'SYN':
            return None
        
        src_ip = event.get('src_ip')
        dst_ip = event.get('dst_ip')
        dst_port = event.get('dport')
        ts = self._parse_ts(event.get('timestamp'))
        action = event.get('action', '')
        
        if not src_ip or not dst_ip:
            return None
        
        self._cleanup(ts)
        self._dst_events[dst_ip].append((ts, src_ip))
        self._src_events.append((ts, dst_ip))
        
        # Check per-destination SYN rate
        dst_syn_count = len(self._dst_events[dst_ip])
        if dst_syn_count >= self.syn_threshold:
            return {
                'attack_type': 'SYN_FLOOD',
                'severity': 'CRITICAL',
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'dst_port': dst_port,
                'proto': 'TCP',
                'description': f"SYN flood detected: {dst_syn_count} SYN packets to {dst_ip} in {self.window_seconds}s",
                'detail': {
                    'syn_count': dst_syn_count,
                    'threshold': self.syn_threshold,
                    'window_seconds': self.window_seconds,
                    'top_sources': self._top_sources(dst_ip, n=10),
                },
            }
        
        return None
    
    def _top_sources(self, dst_ip: str, n: int = 10) -> List[str]:
        """Get the top N source IPs hitting dst_ip."""
        src_counts: Dict[str, int] = defaultdict(int)
        for _, src in self._dst_events.get(dst_ip, []):
            src_counts[src] += 1
        return sorted(src_counts, key=lambda x: src_counts[x], reverse=True)[:n]


class BruteForceDetector:
    """Detects brute force attempts: repeated connections to authentication ports.
    
    Common brute force targets: 22 (SSH), 23 (Telnet), 3389 (RDP), 21 (FTP), 3306/5432 (DB), 8444 (UI)
    """
    
    AUTH_PORTS: Set[int] = {22, 23, 3389, 21, 3306, 5432, 8444, 80, 443, 25, 110, 143, 993, 995}
    
    def __init__(self, auth_threshold: int = 10, window_seconds: int = 60, auth_ports: Optional[Set[int]] = None):
        self.auth_threshold = auth_threshold
        self.window_seconds = window_seconds
        self.auth_ports = auth_ports if auth_ports is not None else self.AUTH_PORTS
        
        # Track: (src_ip, dst_ip, dport) -> list of timestamps
        self._sessions: Dict[Tuple[str, str, int], List[datetime]] = defaultdict(list)
    
    @staticmethod
    def _parse_ts(ts_raw) -> datetime:
        if isinstance(ts_raw, datetime):
            return ts_raw
        if isinstance(ts_raw, str):
            for fmt in (
                '%Y-%m-%dT%H:%M:%S.%f%z',
                '%Y-%m-%dT%H:%M:%S%z', '%Y-%m-%dT%H:%M:%S.%f',
                '%Y-%m-%dT%H:%M:%SZ', '%Y-%m-%dT%H:%M:%S',
                '%Y-%m-%d %H:%M:%S.%f', '%Y-%m-%d %H:%M:%S',
            ):
                try:
                    dt = datetime.strptime(ts_raw, fmt)
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    return dt
                except ValueError:
                    continue
        return datetime.now(timezone.utc)
    
    def _cleanup(self, key: Tuple[str, str, int], now: datetime):
        cutoff = now - timedelta(seconds=self.window_seconds)
        self._sessions[key] = [t for t in self._sessions[key] if t >= cutoff]
    
    def check(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Check if this event is part of a brute force attempt."""
        src_ip = event.get('src_ip')
        dst_ip = event.get('dst_ip')
        dst_port = event.get('dport')
        ts = self._parse_ts(event.get('timestamp'))
        
        if not src_ip or not dst_ip or dst_port is None:
            return None
        
        # Only check authentication ports
        if dst_port not in self.auth_ports:
            return None
        
        key = (src_ip, dst_ip, dst_port)
        self._cleanup(key, ts)
        self._sessions[key].append(ts)
        
        count = len(self._sessions[key])
        if count >= self.auth_threshold:
            return {
                'attack_type': 'BRUTE_FORCE',
                'severity': 'HIGH',
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'dst_port': dst_port,
                'proto': event.get('proto', 'UNKNOWN'),
                'description': f"Brute force detected: {count} attempts from {src_ip} to {dst_ip}:{dst_port} in {self.window_seconds}s",
                'detail': {
                    'attempt_count': count,
                    'threshold': self.auth_threshold,
                    'service': self._service_name(dst_port),
                    'window_seconds': self.window_seconds,
                },
            }
        
        return None
    
    def _service_name(self, port: int) -> str:
        names = {
            22: 'SSH', 23: 'Telnet', 21: 'FTP', 25: 'SMTP',
            110: 'POP3', 143: 'IMAP', 993: 'IMAPS', 995: 'POP3S',
            3306: 'MySQL', 5432: 'PostgreSQL', 3389: 'RDP',
            80: 'HTTP', 443: 'HTTPS', 8444: 'WebUI',
        }
        return names.get(port, f'port-{port}')


class ProbeDetector:
    """Detects network probes: XMAS, NULL, FIN scans and service enumeration attempts.
    
    Also detects ICMP flood and suspicious protocol usage.
    """
    
    def __init__(self, probe_threshold: int = 5, window_seconds: int = 30):
        self.probe_threshold = probe_threshold
        self.window_seconds = window_seconds
        
        # Track: src_ip -> list of (timestamp, flags_or_proto)
        self._scan_events: Dict[str, List[Tuple[datetime, str]]] = defaultdict(list)
    
    @staticmethod
    def _parse_ts(ts_raw) -> datetime:
        if isinstance(ts_raw, datetime):
            return ts_raw
        if isinstance(ts_raw, str):
            for fmt in (
                '%Y-%m-%dT%H:%M:%S.%f%z',
                '%Y-%m-%dT%H:%M:%S%z', '%Y-%m-%dT%H:%M:%S.%f',
                '%Y-%m-%dT%H:%M:%SZ', '%Y-%m-%dT%H:%M:%S',
                '%Y-%m-%d %H:%M:%S.%f', '%Y-%m-%d %H:%M:%S',
            ):
                try:
                    dt = datetime.strptime(ts_raw, fmt)
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    return dt
                except ValueError:
                    continue
        return datetime.now(timezone.utc)
    
    def _cleanup(self, src_ip: str, now: datetime):
        cutoff = now - timedelta(seconds=self.window_seconds)
        self._scan_events[src_ip] = [
            (t, f) for t, f in self._scan_events[src_ip] if t >= cutoff
        ]
    
    def check(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Check if this event indicates a probe/scanning activity."""
        src_ip = event.get('src_ip')
        tcp_flags = event.get('tcp_flags', '')
        proto = event.get('proto', '')
        action = event.get('action', '')
        ts = self._parse_ts(event.get('timestamp'))
        
        if not src_ip:
            return None
        
        if action != 'BLOCK':
            return None
        
        # XMAS scan detection
        if tcp_flags in ('XMAS', 'XS'):
            self._scan_events[src_ip].append((ts, 'XMAS'))
            return {
                'attack_type': 'PROBE',
                'scan_subtype': 'XMAS_SCAN',
                'severity': 'MEDIUM',
                'src_ip': src_ip,
                'dst_ip': event.get('dst_ip'),
                'dst_port': event.get('dport'),
                'proto': 'TCP',
                'description': f"XMAS scan detected from {src_ip}",
                'detail': {'flags': 'XMAS (FIN+PSH+URG)'},
            }
        
        # NULL scan detection
        if tcp_flags in ('NULL', 'FN'):
            self._scan_events[src_ip].append((ts, 'NULL'))
            return {
                'attack_type': 'PROBE',
                'scan_subtype': 'NULL_SCAN',
                'severity': 'MEDIUM',
                'src_ip': src_ip,
                'dst_ip': event.get('dst_ip'),
                'dst_port': event.get('dport'),
                'proto': 'TCP',
                'description': f"NULL scan detected from {src_ip}",
                'detail': {'flags': 'NULL (no flags)'},
            }
        
        # FIN scan detection
        if tcp_flags == 'FIN':
            self._scan_events[src_ip].append((ts, 'FIN'))
            return {
                'attack_type': 'PROBE',
                'scan_subtype': 'FIN_SCAN',
                'severity': 'MEDIUM',
                'src_ip': src_ip,
                'dst_ip': event.get('dst_ip'),
                'dst_port': event.get('dport'),
                'proto': 'TCP',
                'description': f"FIN scan detected from {src_ip}",
                'detail': {'flags': 'FIN only'},
            }
        
        # ICMP probe flood
        if proto == 'ICMP' and action == 'BLOCK':
            self._scan_events[src_ip].append((ts, 'ICMP'))
            self._cleanup(src_ip, ts)
            icmp_count = sum(1 for _, f in self._scan_events[src_ip] if f == 'ICMP')
            if icmp_count >= self.probe_threshold:
                return {
                    'attack_type': 'PROBE',
                    'scan_subtype': 'ICMP_FLOOD',
                    'severity': 'MEDIUM',
                    'src_ip': src_ip,
                    'dst_ip': event.get('dst_ip'),
                    'dst_port': None,
                    'proto': 'ICMP',
                    'description': f"ICMP flood detected: {icmp_count} ICMP probes from {src_ip}",
                    'detail': {'icmp_count': icmp_count},
                }
        
        return None


# ============================================================
# Unified detection orchestrator
# ============================================================


class AttackDetector:
    """Orchestrates all attack detectors, applies deduplication.
    
    Each detector maintains its own internal state (windows, counters).
    The orchestrator collects detections and deduplicates within
    a configurable window to avoid alert flooding.
    """
    
    def __init__(self, dedup_seconds: int = 300, config: Optional[Dict[str, Any]] = None):
        config = config or {}
        
        # Initialize detectors with configurable thresholds
        self.port_scan = PortScanDetector(
            vertical_threshold=config.get('port_scan_vertical', 15),
            horizontal_threshold=config.get('port_scan_horizontal', 10),
            window_seconds=config.get('port_scan_window', 120),
        )
        
        self.syn_flood = SYNFloodDetector(
            syn_threshold=config.get('syn_flood_threshold', 30),
            window_seconds=config.get('syn_flood_window', 30),
        )
        
        self.brute_force = BruteForceDetector(
            auth_threshold=config.get('brute_force_threshold', 10),
            window_seconds=config.get('brute_force_window', 60),
        )
        
        self.probe = ProbeDetector(
            probe_threshold=config.get('probe_threshold', 5),
            window_seconds=config.get('probe_window', 30),
        )
        
        # Deduplication: last seen key -> timestamp
        self._dedup: Dict[str, float] = {}
        self._dedup_seconds = dedup_seconds
    
    def check_event(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Run all detectors against an event and return any detected attacks."""
        detections = []
        
        # Port scan detection
        ps = self.port_scan.check(event)
        if ps:
            detections.append(ps)
        
        # SYN flood detection
        sf = self.syn_flood.check(event)
        if sf:
            detections.append(sf)
        
        # Brute force detection
        bf = self.brute_force.check(event)
        if bf:
            detections.append(bf)
        
        # Probe detection
        pd = self.probe.check(event)
        if pd:
            detections.append(pd)
        
        # Apply dedup
        return self._deduplicate(detections, event.get('timestamp'))
    
    def _deduplicate(self, detections: List[Dict[str, Any]], ts: Optional[datetime] = None) -> List[Dict[str, Any]]:
        """Deduplicate detections within the configured window."""
        now = time.time()
        self._dedup = {k: v for k, v in self._dedup.items() if now - v < self._dedup_seconds}
        
        results = []
        for det in detections:
            # Create a unique key per detection
            key = self._dedup_key(det)
            if key in self._dedup:
                continue
            self._dedup[key] = now
            results.append(det)
        
        return results
    
    def _dedup_key(self, det: Dict[str, Any]) -> str:
        """Create a dedup key from detection attributes."""
        return f"{det['attack_type']}|{det['src_ip']}|{det.get('dst_port', 'any')}|{det.get('scan_subtype', '')}"
