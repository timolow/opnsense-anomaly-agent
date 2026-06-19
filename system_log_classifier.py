#!/usr/bin/env python3
"""
System Log Classifier — ML learning for OPNsense system logs.

Classifies and learns normal behavior patterns for system logs (ntpd, DNS,
DHCP, ARP, etc.) and detects anomalies:
- Unusual volume spikes for a service
- New services appearing unexpectedly
- Services with abnormal IP distributions
- Anomalous log-level patterns (error bursts, etc.)

Unlike rule_classifier.py which focuses on firewall rules, this tracks
system-level activity: NTP syncs, DNS queries/replies, DHCP transactions,
ARP announcements, daemon restarts, etc.
"""

import os
import json
import logging
import re
from datetime import datetime, timezone, timedelta
from collections import defaultdict, Counter, deque
from typing import Dict, Any, List, Optional, Set
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# Classification thresholds
MIN_SAMPLES = 20
VOLATILE_WINDOW_MINUTES = 60
SPIKE_ZSCORE = 3.0


# Known OPNsense service names from syslog process field
KNOWN_SERVICES = {
    'ntpd', 'ntpd_sync', 'dns', 'unbound', 'dnsmasq', 'dhcpleases',
    'dhcpd', 'arp', 'rtsold', 'kernel', 'system', 'cron', 'sudo',
    'sshd', 'lighttpd', 'php-fpm', 'omv-engined', 'snmpd', 'avahi',
    'connmand', 'networkd', 'resolvconf', 'dhcpcd', 'firewall',
    'filterlog', 'vpn', 'openvpn', 'wireguard', 'pfsense',
    'usbhid-ups', 'lockout_handler', 'configd', 'zenarmor', 'zenarmor.service',
}

# Services trusted to never trigger NEW_SERVICE alerts (OPNsense internal daemons)
TRUSTED_SERVICES = {
    'ntpd', 'dns', 'unbound', 'dhcp', 'arp', 'cron', 'sudo', 'sshd',
    'lighttpd', 'php-fpm', 'omv-engined', 'snmpd', 'kernel', 'system',
    'firewall', 'filterlog', 'vpn', 'openvpn', 'wireguard',
    'usbhid-ups', 'lockout_handler', 'configd', 'zenarmor',
    'omniservice', 'captiveportal', 'ntpctl', 'dhcpleases',
}


def _is_ip_address(s: str) -> bool:
    """Check if a string is an IPv4 or IPv6 address (or prefix thereof)."""
    if not s:
        return False
    # IPv4 pattern: digits and dots only, starts with a digit
    if re.match(r'^\d+\.\d+', s):
        return True
    # IPv6 pattern: hex digits and colons, contains at least one colon
    if ':' in s and re.match(r'^[0-9a-fA-F:.]+$', s):
        # Must look like an IP (has hex groups, not just random colons)
        parts = s.split(':')
        if len(parts) >= 2 and all(p == '' or all(c in '0123456789abcdefABCDEF' for c in p) for p in parts):
            return True
    return False


def _detect_service(raw: str, process: Optional[str]) -> str:
    """Detect the service/daemon from raw log and process name."""
    if process:
        proc = process.lower().strip()
        if proc:
            # Skip IP addresses that were misparsed as process names
            if _is_ip_address(proc):
                return 'unknown'
            for svc in KNOWN_SERVICES:
                if svc in proc:
                    return svc
            return proc

    patterns = [
        (r'ntpd|ntp', 'ntpd'),
        (r'dns|unbound|dnsmasq', 'dns'),
        (r'dhcp', 'dhcp'),
        (r'arp|ARP', 'arp'),
        (r'rtsold', 'rtsold'),
        (r'sshd', 'sshd'),
        (r'cron', 'cron'),
        (r'sudo', 'sudo'),
        (r'kernel', 'kernel'),
        (r'vpn|openvpn|wg', 'vpn'),
    ]
    for pattern, svc in patterns:
        if re.search(pattern, raw):
            return svc
    return process or 'unknown'


def _detect_log_level(raw: str) -> str:
    """Detect log level from message content."""
    raw_lower = raw.lower()
    if any(w in raw_lower for w in ['error', 'fail', 'critical']):
        return 'error'
    if any(w in raw_lower for w in ['warn', 'warning']):
        return 'warning'
    if any(w in raw_lower for w in ['info', 'notice']):
        return 'info'
    return 'debug'


@dataclass
class ServiceProfile:
    """Profile of a system service's normal behavior."""
    service: str
    action_counts: Counter = field(default_factory=Counter)
    src_ips: Set = field(default_factory=set)
    dst_ips: Set = field(default_factory=set)
    event_history: deque = field(default_factory=lambda: deque(maxlen=10000))
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    total_events: int = 0
    hourly_counts: Counter = field(default_factory=Counter)

    @property
    def is_new(self) -> bool:
        return self.total_events < MIN_SAMPLES

    @property
    def dominant_log_level(self) -> Optional[str]:
        if not self.action_counts:
            return None
        return self.action_counts.most_common(1)[0][0]

    @property
    def unique_src_count(self) -> int:
        return len(self.src_ips)

    @property
    def unique_dst_count(self) -> int:
        return len(self.dst_ips)

    def get_spike_zscore(self, current_count: int) -> float:
        """Calculate z-score for current count vs historical mean."""
        if not self.hourly_counts or len(self.hourly_counts) < MIN_SAMPLES:
            return 0.0
        counts = list(self.hourly_counts.values())
        n = len(counts)
        mean = sum(counts) / n
        variance = sum((c - mean) ** 2 for c in counts) / (n - 1)
        if variance == 0:
            return 0.0
        stddev = variance ** 0.5
        return (current_count - mean) / stddev


class SystemLogClassifier:
    """
    Classifies and learns system log patterns.

    Tracks:
    - Per-service event volume baselines
    - Per-service IP distributions
    - New service detection
    - Log level anomalies (error bursts)
    """

    def __init__(self, min_samples=MIN_SAMPLES, spike_zscore=SPIKE_ZSCORE):
        self.min_samples = min_samples
        self.spike_zscore = spike_zscore
        self.service_profiles: Dict[str, ServiceProfile] = {}
        self.total_events = 0
        self.events_by_service: Counter = Counter()
        self.events_by_level: Counter = Counter()
        self.anomaly_log: List[Dict] = []
        self._new_services_seen: Set[str] = set()

        logger.info("SystemLogClassifier initialized (min_samples=%d, spike_zscore=%.1f)",
                    min_samples, spike_zscore)

    def process_event(self, event: Dict[str, Any]):
        """Process a single event and update service profiles."""
        self.total_events += 1
        raw = event.get('raw', event.get('raw_message', ''))
        process = event.get('process')
        log_level = event.get('log_level', _detect_log_level(raw))
        service = _detect_service(raw, process)
        src_ip = event.get('src_ip')
        dst_ip = event.get('dst_ip')

        self.events_by_service[service] += 1
        self.events_by_level[log_level] += 1

        if service not in self.service_profiles:
            self.service_profiles[service] = ServiceProfile(service=service)
            self._new_services_seen.add(service)
            logger.info("New service detected: %s (total events so far: 1)", service)
        else:
            self._new_services_seen.discard(service)

        profile = self.service_profiles[service]
        profile.total_events += 1
        profile.action_counts[log_level] += 1

        if src_ip:
            profile.src_ips.add(src_ip)
        if dst_ip:
            profile.dst_ips.add(dst_ip)

        ts = event.get('timestamp', '')
        if ts:
            try:
                if 'T' in str(ts):
                    dt = datetime.fromisoformat(str(ts))
                else:
                    dt = datetime.strptime(str(ts)[:19], "%Y-%m-%d %H:%M:%S")
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                profile.event_history.append(dt)
                hour_key = dt.strftime('%Y-%m-%d %H')
                profile.hourly_counts[hour_key] += 1
                if profile.first_seen is None or dt < profile.first_seen:
                    profile.first_seen = dt
                if profile.last_seen is None or dt > profile.last_seen:
                    profile.last_seen = dt
            except Exception as e:
                logger.debug("Timestamp parsing error for service %s: %s", service, e)

    def detect_anomalies(self) -> List[Dict[str, Any]]:
        """Detect anomalies in system log patterns."""
        anomalies = []
        now = datetime.now(timezone.utc)
        now_str = now.strftime('%Y-%m-%d %H')

        for name, profile in self.service_profiles.items():
            # 1. New services (first appearance) — skip trusted OPNsense services
            if name in self._new_services_seen and profile.total_events <= 5:
                if name in TRUSTED_SERVICES:
                    # Trusted service — just log it, don't alert
                    self._new_services_seen.discard(name)
                    continue
                anomalies.append({
                    'type': 'NEW_SERVICE',
                    'severity': 'MEDIUM' if profile.total_events <= 2 else 'LOW',
                    'service': name,
                    'events': profile.total_events,
                    'description': f"New service '{name}' appeared with {profile.total_events} events",
                    'src_ips': list(profile.src_ips)[:10],
                })

            # 2. Volume spike detection
            if name in self._new_services_seen or profile.total_events < MIN_SAMPLES:
                continue

            current_count = profile.hourly_counts.get(now_str, 0)
            if current_count == 0:
                continue

            z = profile.get_spike_zscore(current_count)
            if z > self.spike_zscore:
                anomalies.append({
                    'type': 'VOLUME_SPIKE',
                    'severity': 'HIGH' if z > 5 else 'MEDIUM',
                    'service': name,
                    'current_count': current_count,
                    'z_score': round(z, 2),
                    'description': f"Service '{name}' volume spike: {current_count} events/hour (z-score={z:.1f})",
                })

            # 3. Error burst detection
            if profile.action_counts.get('error', 0) > 5 and profile.total_events > 10:
                error_ratio = profile.action_counts['error'] / profile.total_events
                if error_ratio > 0.3:
                    anomalies.append({
                        'type': 'ERROR_BURST',
                        'severity': 'HIGH' if error_ratio > 0.5 else 'MEDIUM',
                        'service': name,
                        'error_count': profile.action_counts['error'],
                        'total_events': profile.total_events,
                        'error_ratio': round(error_ratio, 2),
                        'description': f"Service '{name}' has high error ratio: {error_ratio:.0%} ({profile.action_counts['error']}/{profile.total_events})",
                    })

            # 4. Unexpected IP diversity
            if profile.total_events >= MIN_SAMPLES and profile.unique_src_count > 50:
                anomalies.append({
                    'type': 'HIGH_IP_DIVERSITY',
                    'severity': 'MEDIUM',
                    'service': name,
                    'unique_src_ips': profile.unique_src_count,
                    'description': f"Service '{name}' communicating with {profile.unique_src_count} unique source IPs (high diversity)",
                })

        return anomalies

    def get_service_summary(self) -> Dict[str, Any]:
        """Get summary of all service profiles."""
        services = []
        for name, profile in self.service_profiles.items():
            services.append({
                'service': name,
                'total_events': profile.total_events,
                'log_level_dist': dict(profile.action_counts),
                'dominant_level': profile.dominant_log_level,
                'unique_src_ips': profile.unique_src_count,
                'unique_dst_ips': profile.unique_dst_count,
                'is_new': profile.is_new,
                'first_seen': profile.first_seen.isoformat() if profile.first_seen else None,
                'last_seen': profile.last_seen.isoformat() if profile.last_seen else None,
            })

        return {
            'total_system_events': self.total_events,
            'services_tracked': len(self.service_profiles),
            'new_services': list(self._new_services_seen),
            'services_by_volume': dict(self.events_by_service.most_common(15)),
            'log_levels': dict(self.events_by_level.most_common()),
            'service_details': sorted(services, key=lambda x: -x['total_events']),
        }

    def save_state(self, filepath: Optional[str] = None):
        """Save system log classifier state to disk."""
        if filepath is None:
            base_dir = os.environ.get("AGENT_DATA_DIR", "/app/agent_data")
            filepath = os.path.join(base_dir, "system_log_classifier_state.json")

        state = {
            'services': {name: {
                'service': p.service,
                'action_counts': dict(p.action_counts),
                'total_events': p.total_events,
                'unique_src_ips': len(p.src_ips),
                'unique_dst_ips': len(p.dst_ips),
                'hourly_counts': dict(p.hourly_counts),
                'first_seen': p.first_seen.isoformat() if p.first_seen else None,
                'last_seen': p.last_seen.isoformat() if p.last_seen else None,
            } for name, p in self.service_profiles.items()},
            'events_by_service': dict(self.events_by_service.most_common(100)),
            'events_by_level': dict(self.events_by_level),
            'new_services': list(self._new_services_seen),
        }

        with open(filepath, 'w') as f:
            json.dump(state, f, indent=2, default=str)
        logger.info("System log classifier state saved to %s (%d services)", filepath, len(self.service_profiles))

    def load_state(self, filepath: Optional[str] = None):
        """Load system log classifier state from disk."""
        if filepath is None:
            base_dir = os.environ.get("AGENT_DATA_DIR", "/app/agent_data")
            filepath = os.path.join(base_dir, "system_log_classifier_state.json")

        if not os.path.exists(filepath):
            logger.info("No system log classifier state file found at %s", filepath)
            return

        try:
            with open(filepath, 'r') as f:
                state = json.load(f)

            for name, data in state.get('services', {}).items():
                profile = ServiceProfile(service=name)
                profile.action_counts = Counter(data.get('action_counts', {}))
                profile.total_events = data.get('total_events', 0)
                profile.hourly_counts = Counter(data.get('hourly_counts', {}))
                profile.first_seen = datetime.fromisoformat(data['first_seen']) if data.get('first_seen') else None
                profile.last_seen = datetime.fromisoformat(data['last_seen']) if data.get('last_seen') else None
                self.service_profiles[name] = profile

            self.events_by_service = Counter(state.get('events_by_service', {}))
            self.events_by_level = Counter(state.get('events_by_level', {}))
            self._new_services_seen = set(state.get('new_services', []))

            logger.info("System log classifier state loaded from %s (%d services)", filepath, len(self.service_profiles))
        except Exception as e:
            logger.error("Failed to load system log classifier state: %s", e)
