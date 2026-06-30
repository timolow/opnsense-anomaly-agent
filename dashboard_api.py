#!/usr/bin/env python3
"""
Dashboard API for OPNsense Anomaly Detection

Provides clean REST endpoints for the new dashboard frontend.
Consolidates data from all sources into actionable intelligence.

Usage:
    from dashboard_api import run_server
    run_server(port=8766, threat_engine=engine, baseline_engine=baseline, db_connection=db)
"""

import json
import logging
import math
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Callable

logger = logging.getLogger(__name__)

class DashboardAPI:
    """REST API for dashboard frontend."""
    
    def __init__(self, threat_engine=None, baseline_engine=None, db_connection=None):
        self.threat_engine = threat_engine
        self.baseline_engine = baseline_engine
        self.db = db_connection
        
        # Register routes
        self.routes: Dict[str, Callable] = {
            "/api/stats": self._get_stats,
            "/api/threats": self._get_threats,
            "/api/timeline": self._get_timeline,
            "/api/rules": self._get_rules,
            "/api/baselines": self._get_baselines,
            "/api/settings": self._get_settings,
            "/api/health": self._get_health
        }
    
    def _get_stats(self, params: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """Get high-level statistics."""
        stats = {
            "total_events": 0,
            "total_ips": 0,
            "threats_detected": 0,
            "critical_threats": 0,
            "high_threats": 0,
            "medium_threats": 0,
            "low_threats": 0,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
        try:
            # Get event counts from normalized_events (grouped by source)
            # DEPRECATED tables (firewall_events, http_events, ids_events,
            # zenarmor_events, nginx_events) were renamed to *_deprecated in V22.
            result = self.db.execute("""
                SELECT source, COUNT(*) as cnt
                FROM normalized_events
                GROUP BY source
            """).fetchall()

            if result:
                by_source = {row[0]: row[1] for row in result}
                stats["total_events"] = sum(by_source.values())
                stats["by_source"] = {
                    "firewall": by_source.get("firewall", 0),
                    "http": by_source.get("http", 0),
                    "ids": by_source.get("ids", 0),
                    "zenarmor": by_source.get("zenarmor", 0),
                    "nginx": by_source.get("nginx", 0),
                    "unifi": by_source.get("unifi", 0),
                }

            # Get unique IPs from normalized_events
            result = self.db.execute(
                "SELECT COUNT(DISTINCT src_ip) FROM normalized_events "
                "WHERE src_ip IS NOT NULL AND src_ip != ''"
            ).fetchone()
            if result:
                stats["total_ips"] = result[0]
            
            # Get threat counts from threat engine
            if self.threat_engine:
                for ip, profile in self.threat_engine._ip_profiles.items():
                    score = profile.unified_score
                    if score >= 90:
                        stats["critical_threats"] += 1
                    elif score >= 70:
                        stats["high_threats"] += 1
                    elif score >= 40:
                        stats["medium_threats"] += 1
                    elif score >= 20:
                        stats["low_threats"] += 1
                
                stats["threats_detected"] = stats["critical_threats"] + stats["high_threats"] + \
                                          stats["medium_threats"] + stats["low_threats"]
            
        except Exception as e:
            logger.error(f"Failed to get stats: {e}")
            stats["error"] = str(e)
        
        return stats
    
    def _get_threats(self, params: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """Get current threats sorted by severity."""
        threats = []
        
        if self.threat_engine:
            # Get all IPs with threat scores
            for ip, profile in self.threat_engine._ip_profiles.items():
                score = self.threat_engine.score_ip(ip)
                if score >= 20:  # Only return IPs with at least low threat
                    threats.append({
                        "ip": ip,
                        "score": score,
                        "level": self.threat_engine.get_threat_level(ip),
                        "signals": len(profile.signals),
                        "total_events": profile.total_events,
                        "last_seen": profile.last_seen.isoformat() if profile.last_seen else None,
                        "geo_info": profile.geo_info
                    })
        
        # Sort by score descending
        threats.sort(key=lambda x: x["score"], reverse=True)
        
        return {
            "threats": threats[:50],
            "total_threats": len(threats),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    
    def _get_timeline(self, params: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """Get event timeline data."""
        timeline = []
        
        try:
            # Get hourly event counts
            results = self.db.execute("""
                SELECT 
                    strftime('%Y-%m-%d %H:00', timestamp) as hour,
                    COUNT(*) as events,
                    SUM(CASE WHEN action = 'block' THEN 1 ELSE 0 END) as blocks,
                    SUM(CASE WHEN action = 'pass' THEN 1 ELSE 0 END) as passes
                FROM firewall_events
                WHERE timestamp > datetime('now', '-24 hours')
                GROUP BY hour
                ORDER BY hour
            """).fetchall()
            
            for result in results:
                timeline.append({
                    "hour": result[0],
                    "events": result[1],
                    "blocks": result[2],
                    "passes": result[3]
                })
        
        except Exception as e:
            logger.error(f"Failed to get timeline: {e}")
        
        return {
            "timeline": timeline,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    
    def _get_rules(self, params: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """Get firewall rule health."""
        rules = []
        
        try:
            # Get rule baselines
            results = self.db.execute("""
                SELECT rule, avg_events_per_hour, std_events_per_hour,
                       max_events_per_hour, pass_ratio, block_ratio,
                       sample_count, last_updated
                FROM rule_baselines
                ORDER BY sample_count DESC
                LIMIT 50
            """).fetchall()
            
            for result in results:
                rule_name = result[0]
                baseline = self.baseline_engine.get_baseline(rule_name) if self.baseline_engine else None
                
                # Calculate health score
                health_score = 100.0
                anomaly_reasons = []
                
                if baseline:
                    # Check volume anomaly
                    current_volume = self._get_current_rule_volume(rule_name)
                    if baseline.avg_events_per_hour > 0:
                        volume_ratio = current_volume / baseline.avg_events_per_hour
                        if volume_ratio > 3:
                            health_score -= 30
                            anomaly_reasons.append("high_volume")
                        elif volume_ratio < 0.1:
                            health_score -= 20
                            anomaly_reasons.append("low_volume")
                
                rules.append({
                    "rule": rule_name,
                    "health_score": max(0, health_score),
                    "avg_volume": result[1],
                    "pass_ratio": result[4],
                    "block_ratio": result[5],
                    "sample_count": result[6],
                    "anomaly_reasons": anomaly_reasons
                })
        
        except Exception as e:
            logger.error(f"Failed to get rules: {e}")
        
        return {
            "rules": rules,
            "total_rules": len(rules),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    
    def _get_baselines(self, params: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """Get baseline statistics."""
        baselines = []
        
        if self.baseline_engine:
            for key, baseline in self.baseline_engine._baselines.items():
                baselines.append({
                    "rule": baseline.rule,
                    "ip": baseline.ip,
                    "hour": baseline.hour,
                    "avg_events_per_hour": baseline.avg_events_per_hour,
                    "std_events_per_hour": baseline.std_events_per_hour,
                    "pass_ratio": baseline.pass_ratio,
                    "block_ratio": baseline.block_ratio,
                    "sample_count": baseline.sample_count,
                    "confidence": baseline.confidence_score(),
                    "last_updated": baseline.last_updated.isoformat() if baseline.last_updated else None
                })
        
        return {
            "baselines": baselines[:50],
            "total_baselines": len(baselines),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    
    def _get_settings(self, params: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """Get configuration and status."""
        return {
            "settings": {
                "threat_score_critical": 90,
                "threat_score_high": 70,
                "threat_score_medium": 40,
                "threat_score_low": 20,
                "signal_decay_rate": 0.95,
                "baseline_window_hours": 24,
                "min_events_for_baseline": 10
            },
            "status": {
                "total_ips_tracked": len(self.threat_engine._ip_profiles) if self.threat_engine else 0,
                "total_baselines": len(self.baseline_engine._baselines) if self.baseline_engine else 0,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        }
    
    def _get_health(self, params: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """Get system health status."""
        return {
            "status": "healthy",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    
    def _get_current_rule_volume(self, rule: str) -> float:
        """Get current volume for a rule."""
        try:
            result = self.db.execute("""
                SELECT COUNT(*) FROM firewall_events 
                WHERE rule = %s AND timestamp > NOW() - INTERVAL '1 hour'
            """, (rule,)).fetchone()
            return result[0] if result else 0
        except Exception:
            return 0

class DashboardRequestHandler(BaseHTTPRequestHandler):
    """HTTP request handler for dashboard API."""
    
    def do_GET(self):
        """Handle GET requests."""
        parsed_path = urlparse(self.path)
        path = parsed_path.path
        params = parse_qs(parsed_path.query)
        
        # Get the dashboard API instance
        dashboard_api = self.server.dashboard_api
        
        # Route request
        if path in dashboard_api.routes:
            response = dashboard_api.routes[path](params)
        else:
            response = {"error": "Not found", "path": path}
        
        # Send response
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(response).encode())
    
    def log_message(self, format, *args):
        """Suppress default logging."""
        pass

def run_server(port: int = 8766, threat_engine=None, baseline_engine=None, db_connection=None):
    """Run the dashboard API server."""
    dashboard_api = DashboardAPI(threat_engine, baseline_engine, db_connection)
    
    server = HTTPServer(("0.0.0.0", port), DashboardRequestHandler)
    server.dashboard_api = dashboard_api  # type: ignore
    
    logger.info(f"Dashboard API running on port {port}")
    server.serve_forever()