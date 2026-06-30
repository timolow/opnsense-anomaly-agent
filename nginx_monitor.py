#!/usr/bin/env python3
"""Nginx web server traffic monitor.

Tracks nginx request patterns, detects web-specific attack anomalies
such as path traversal, brute force, DDoS, scanner probes, and 
invalid user agents.

Attack types:
- PATH_TRAVERSAL: Attempts to access files outside web root (e.g. /../../etc/passwd)
- BRUTE_FORCE: Repeated failed auth requests to login endpoints
- DDOS: Extremely high request rate from single IP
- SCAN: Systematic path enumeration (many 404s from same IP)
- INVALID_UA: Known malicious/bot user agents
"""

import re
import time
from datetime import datetime, timezone
from collections import defaultdict, Counter
from typing import Dict, Any, List, Optional
import logging

logger = logging.getLogger(__name__)

# Known dangerous user agents (simplified patterns)
DANGEROUS_UA_PATTERNS = [
    r'(nikto|nmap|sqlmap|masscan|dirbuster|gobuster|ffuf|wfuzz|hydra)',
    r'(python-requests|go-http|curl/|wget/)',
    r'(scanner|bot|crawler|spider)',
    r'(w3af|acunetix|nessus|openvas|qualys)',
]

# Admin/login paths that are targets for brute force
ADMIN_PATHS = [
    r'/admin', r'/login', r'/wp-login', r'/wp-admin', r'/phpmyadmin',
    r'/cpanel', r'/administrator', r'/console', r'/dashboard',
    r'/api/login', r'/oauth/token', r'/auth',
]

# Path traversal patterns
TRAVERSAL_PATTERNS = [
    r'\.\./', r'\.\.\\', r'/etc/passwd', r'/etc/shadow',
    r'/proc/self', r'/windows/system32',
]

# Suspicious HTTP methods for scanning
SCAN_METHODS = {'DELETE', 'PUT', 'PATCH', 'OPTIONS', 'TRACE', 'CONNECT', 'PROPFIND', 'MKCOL'}

# Brute force detection thresholds
BRUTE_FORCE_THRESHOLD = 10  # failed auth attempts in window
BRUTE_FORCE_WINDOW = 300    # 5 minutes in seconds

# DDoS thresholds  
DDOS_THRESHOLD = 100  # requests per minute from single IP


class NginxMonitor:
    """Monitors nginx web traffic for anomalies."""

    def __init__(self, signal_bus=None):
        self.db = None
        self.signal_bus = signal_bus
        self.db = None
        self.vllm_client = None
        
        # Per-IP tracking
        self.ip_requests = defaultdict(list)  # ip -> [timestamp]
        self.ip_failed_auth = defaultdict(list)  # ip -> [(timestamp, path)]
        self.ip_404s = defaultdict(list)  # ip -> [(timestamp, path)]
        
        # Aggregated counts
        self.request_counts = Counter()  # path -> count
        self.ip_request_counts = Counter()  # ip -> count
        self.status_counts = Counter()  # status_code -> count
        self.method_counts = Counter()  # method -> count
        
        # State persistence handled centrally by StatePersistence
        
    def set_db(self, db):
        """Set database reference."""
        self.db = db
        
    def set_vllm_client(self, vllm_client):
        """Set VLLM client for LLM analysis."""
        self.vllm_client = vllm_client
    
    def process_event(self, event: dict):
        """Process a single nginx event.
        
        Tracks patterns, detects anomalies, stores in DB.
        """
        if not event.get('src_ip') or not event.get('path'):
            return
        
        src_ip = event['src_ip']
        path = event['path']
        status_code = event.get('status_code') or 0
        method = event.get('method', 'GET')
        user_agent = event.get('user_agent', '')
        timestamp = event.get('timestamp', '')
        
        now = time.time()
        
        # Store in database
        if self.db:
            try:
                self.db.insert_nginx_event({
                    'timestamp': timestamp,
                    'src_ip': src_ip,
                    'method': method,
                    'path': path,
                    'status_code': status_code,
                    'bytes': event.get('bytes', 0),
                    'request': event.get('request', ''),
                    'user_agent': user_agent,
                    'raw': event.get('raw', ''),
                })
            except Exception as e:
                logger.warning("Failed to store nginx event: %s", e)
        
        # Track per-IP request timestamps
        self.ip_requests[src_ip].append(now)
        self.ip_request_counts[src_ip] += 1
        self.request_counts[path] += 1
        self.method_counts[method] += 1
        if status_code:
            self.status_counts[status_code] += 1
        
        # ── Anomaly Detection ──
        
        # 1. Path traversal detection
        if self._check_path_traversal(path):
            self._alert_nginx_anomaly(
                timestamp=timestamp,
                attack_type='PATH_TRAVERSAL',
                severity='CRITICAL',
                src_ip=src_ip,
                path=path,
                status_code=status_code,
                description=f"Path traversal attempt: {path}",
            )
        
        # 2. Brute force detection (failed auth)
        if status_code and 400 <= status_code < 499:
            # Check if it's an auth-related path
            for admin_path in ADMIN_PATHS:
                if re.search(admin_path, path, re.IGNORECASE):
                    self.ip_failed_auth[src_ip].append((now, path))
                    if self._check_brute_force(src_ip, now):
                        self._alert_nginx_anomaly(
                            timestamp=timestamp,
                            attack_type='BRUTE_FORCE',
                            severity='HIGH',
                            src_ip=src_ip,
                            path=path,
                            status_code=status_code,
                            description=f"Brute force: {self.ip_failed_auth[src_ip][-5:]} failed auth requests",
                        )
                    break
        
        # 3. Scanner detection (many 404s from same IP)
        if status_code == 404:
            self.ip_404s[src_ip].append((now, path))
            if self._check_scanner(src_ip, now):
                self._alert_nginx_anomaly(
                    timestamp=timestamp,
                    attack_type='SCAN',
                    severity='MEDIUM',
                    src_ip=src_ip,
                    path=path,
                    status_code=status_code,
                    description=f"Scanner: high 404 rate from {src_ip}",
                )
        
        # 4. DDoS detection (high request rate)
        if self._check_ddos(src_ip, now):
            self._alert_nginx_anomaly(
                timestamp=timestamp,
                attack_type='DDOS',
                severity='HIGH',
                src_ip=src_ip,
                path=path,
                status_code=status_code,
                description=f"DDoS indicator: high request rate from {src_ip}",
            )
        
        # 5. Invalid/malicious user agent detection
        if user_agent:
            for pattern in DANGEROUS_UA_PATTERNS:
                if re.search(pattern, user_agent, re.IGNORECASE):
                    self._alert_nginx_anomaly(
                        timestamp=timestamp,
                        attack_type='INVALID_UA',
                        severity='LOW',
                        src_ip=src_ip,
                        path=path,
                        status_code=status_code,
                        description=f"Known malicious UA: {user_agent[:80]}",
                    )
                    break
        
        # 6. Suspicious HTTP method detection
        if method in SCAN_METHODS and status_code and status_code >= 400:
            self._alert_nginx_anomaly(
                timestamp=timestamp,
                attack_type='SCAN',
                severity='LOW',
                src_ip=src_ip,
                path=path,
                status_code=status_code,
                description=f"Suspicious method {method} with {status_code} response",
            )
    
    def _check_path_traversal(self, path: str) -> bool:
        """Check if path contains traversal patterns."""
        return any(re.search(p, path) for p in TRAVERSAL_PATTERNS)
    
    def _check_brute_force(self, ip: str, now: float) -> bool:
        """Check if IP has too many failed auth attempts in window."""
        cutoff = now - BRUTE_FORCE_WINDOW
        self.ip_failed_auth[ip] = [
            (t, p) for t, p in self.ip_failed_auth[ip] if t > cutoff
        ]
        return len(self.ip_failed_auth[ip]) >= BRUTE_FORCE_THRESHOLD
    
    def _check_scanner(self, ip: str, now: float) -> bool:
        """Check if IP has too many 404 errors in a short window."""
        cutoff = now - 60  # 1 minute
        self.ip_404s[ip] = [
            (t, p) for t, p in self.ip_404s[ip] if t > cutoff
        ]
        return len(self.ip_404s[ip]) >= 15
    
    def _check_ddos(self, ip: str, now: float) -> bool:
        """Check if IP has too many requests per minute."""
        cutoff = now - 60  # 1 minute
        self.ip_requests[ip] = [
            t for t in self.ip_requests[ip] if t > cutoff
        ]
        return len(self.ip_requests[ip]) >= DDOS_THRESHOLD
    
    def _alert_nginx_anomaly(
        self, timestamp: str, attack_type: str, severity: str,
        src_ip: str, path: str, status_code: int, description: str
    ):
        """Store a nginx anomaly in the database and emit to signal bus."""
        if not self.db:
            return
        
        try:
            self.db.insert_nginx_anomaly({
                'timestamp': timestamp,
                'attack_type': attack_type,
                'severity': severity,
                'src_ip': src_ip,
                'path': path,
                'status_code': status_code,
                'description': description,
                'detail': {'attack_type': attack_type, 'severity': severity},
                'alert_sent': False,
            })
            logger.info("Nginx anomaly: %s — %s", attack_type, description[:80])
        except Exception as e:
            logger.warning("Failed to store nginx anomaly: %s", e)
        
        # Emit to signal bus
        if self.signal_bus:
            nginx_signal_map = {
                'PATH_TRAVERSAL': 'path_traversal',
                'BRUTE_FORCE': 'http_brute_force',
                'SCAN': 'http_scan',
                'DDOS': 'http_ddos',
                'INVALID_UA': 'invalid_ua',
            }
            self.signal_bus.emit(
                source="nginx",
                signal_type=nginx_signal_map.get(attack_type, attack_type.lower().replace(' ', '_')),
                severity=severity.lower(),
                ip=src_ip,
                metadata={
                    "path": path,
                    "status_code": status_code,
                    "description": description,
                },
            )
    
    def get_summary(self, since_hours: int = 24) -> Dict[str, Any]:
        """Get nginx traffic summary from database."""
        if not self.db:
            return {
                'total_requests': 0, 'by_method': {}, 'by_status': {},
                'status_ok': 0, 'status_client_err': 0, 'status_server_err': 0,
                'unique_ips': 0, 'top_ips': [], 'top_paths': [],
                'not_found_404': 0, 'anomalies_by_type': {},
            }
        return self.db.get_nginx_summary(since_hours)
    
    def get_anomalies(self, limit: int = 50) -> List[Dict]:
        """Get recent nginx anomalies."""
        if not self.db:
            return []
        return self.db.get_nginx_anomalies(limit)
    
    def get_top_paths_timeline(self, hours: int = 24) -> List[Dict]:
        """Get top path request counts over time."""
        if not self.db:
            return []
        return self.db.get_nginx_top_paths_timeline(hours)
