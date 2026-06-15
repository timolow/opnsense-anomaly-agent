"""
State persistence for OPNsense anomaly detection agent.

Saves and restores:
- StatisticalModel baselines (running stats: count, mean, m2, values)
- AttackDetector windows (port scan, SYN flood, brute force, probe events)
- NetworkClassifier IP tracking data
- GeoDetector country tracking
- Agent counters (event_count, anomaly_count, uptime_offset)

State is saved to a JSON file and loaded on startup.
Time-windowed state is pruned on load to remove stale data older than
each detector's window.
"""

import json
import logging
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


class StatePersistence:
    """Saves and restores agent state across restarts."""
    
    def __init__(self, state_file: Optional[str] = None):
        if state_file is None:
            self.state_file = Path(__file__).parent / "agent_data" / "state.json"
        else:
            self.state_file = Path(state_file)
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        self._last_save = 0
        self._save_interval = 300  # save every 5 minutes
    
    def save(self, agent) -> None:
        """Save agent state to file."""
        now = time.time()
        if now - self._last_save < self._save_interval:
            return
        
        try:
            state = {
                "version": 1,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "agent_counters": {
                    "event_count": agent.event_count,
                    "anomaly_count": agent.anomaly_count,
                    "start_time": agent.start_time,
                    "last_status": agent.last_status,
                    "last_learn": agent.last_learn,
                },
                "statistical_model": self._save_statistical_model(agent),
                "attack_detector": self._save_attack_detector(agent),
                "network_classifier": self._save_network_classifier(agent),
                "geo_detector": self._save_geo_detector(agent),
                "reverse_dns": self._save_reverse_dns(agent),
            }
            
            with open(self.state_file, "w") as f:
                json.dump(state, f, indent=2, default=str)
            
            self._last_save = now
            logger.info("Agent state saved to %s", self.state_file)
            
        except Exception as e:
            logger.warning("Failed to save agent state: %s", e)
    
    def load(self, agent) -> None:
        """Load agent state from file."""
        if not self.state_file.exists():
            logger.info("No saved state file found — starting fresh")
            return
        
        try:
            with open(self.state_file) as f:
                state = json.load(f)
            
            version = state.get("version", 0)
            logger.info("Loading agent state from %s (v%d)", self.state_file, version)
            
            # Restore agent counters
            counters = state.get("agent_counters", {})
            if counters:
                agent.event_count = counters.get("event_count", 0)
                agent.anomaly_count = counters.get("anomaly_count", 0)
                # Don't restore start_time — that would make uptime look wrong
                # Agent starts fresh with new uptime
                logger.info(
                    "Restored counters: events=%d, anomalies=%d",
                    agent.event_count, agent.anomaly_count,
                )
            
            # Restore sub-modules
            self._load_statistical_model(agent, state.get("statistical_model", {}))
            self._load_attack_detector(agent, state.get("attack_detector", {}))
            self._load_network_classifier(agent, state.get("network_classifier", {}))
            self._load_geo_detector(agent, state.get("geo_detector", {}))
            self._load_reverse_dns(agent, state.get("reverse_dns", {}))
            
            logger.info("Agent state loaded successfully")
            
        except Exception as e:
            logger.warning("Failed to load agent state: %s — starting fresh", e)
    
    # ── StatisticalModel persistence ─────────────────────────────────
    
    def _save_statistical_model(self, agent) -> Dict:
        """Save statistical model baselines."""
        baselines = {}
        for name, baseline in agent.stat_model._baselines.items():
            if baseline.running_stats.count > 0:
                baselines[name] = {
                    "count": baseline.running_stats.count,
                    "mean": baseline.running_stats.mean,
                    "m2": baseline.running_stats.m2,
                    "values": list(baseline.running_stats._values),
                    "threshold": baseline.anomaly_threshold,
                    "min_samples": baseline.min_samples,
                    "window_minutes": baseline.window_minutes,
                }
        return baselines
    
    def _load_statistical_model(self, agent, saved_baselines: Dict) -> None:
        """Load and restore statistical model baselines."""
        loaded = 0
        for name, data in saved_baselines.items():
            try:
                stats = agent.stat_model.get_baseline(name).running_stats
                stats.count = data["count"]
                stats.mean = data["mean"]
                stats.m2 = data["m2"]
                stats._values = data.get("values", [])
                
                if "threshold" in data:
                    agent.stat_model._baselines[name].anomaly_threshold = data["threshold"]
                if "min_samples" in data:
                    agent.stat_model._baselines[name].min_samples = data["min_samples"]
                
                loaded += 1
            except Exception as e:
                logger.warning("Failed to restore baseline '%s': %s", name, e)
        
        if loaded > 0:
            logger.info("Restored %d statistical baselines", loaded)
    
    # ── AttackDetector persistence ───────────────────────────────────
    
    def _save_attack_detector(self, agent) -> Dict:
        """Save attack detector event windows."""
        now = datetime.now(timezone.utc)
        data = {}
        
        # Port scan events
        ps_events = {}
        for src_ip, events in agent.attack_detector.port_scan._events.items():
            # Keep only events within the window (120s default)
            window = agent.attack_detector.port_scan.window_seconds
            cutoff = now - timedelta(seconds=window)
            kept = [(t.isoformat(), d, p) for t, d, p in events if t >= cutoff]
            if kept:
                ps_events[src_ip] = kept
        
        if ps_events:
            data["port_scan_events"] = ps_events
        
        # SYN flood events
        sf_events = {}
        for key, events in agent.attack_detector.syn_flood._events.items():
            window = agent.attack_detector.syn_flood.window_seconds
            cutoff = now - timedelta(seconds=window)
            kept = [(t.isoformat(),) for t in events if t >= cutoff]
            if kept:
                sf_events[key] = {"events": kept, "count": len(kept)}
        
        if sf_events:
            data["syn_flood_events"] = sf_events
        
        # Brute force events
        bf_events = {}
        for key, events in agent.attack_detector.brute_force._events.items():
            window = agent.attack_detector.brute_force.window_seconds
            cutoff = now - timedelta(seconds=window)
            kept = [(t.isoformat(), ip, port) for t, ip, port in events if t >= cutoff]
            if kept:
                bf_events[key] = {"events": kept, "count": len(kept)}
        
        if bf_events:
            data["brute_force_events"] = bf_events
        
        # Probe events
        pr_events = {}
        for src_ip, events in agent.attack_detector.probe._events.items():
            window = agent.attack_detector.probe.window_seconds
            cutoff = now - timedelta(seconds=window)
            kept = [(t.isoformat(), d, p, flags) for t, d, p, flags in events if t >= cutoff]
            if kept:
                pr_events[src_ip] = kept
        
        if pr_events:
            data["probe_events"] = pr_events
        
        return data
    
    def _load_attack_detector(self, agent, saved_data: Dict) -> None:
        """Load and restore attack detector event windows."""
        from datetime import datetime
        
        loaded = 0
        
        # Port scan events
        if "port_scan_events" in saved_data:
            now = datetime.now(timezone.utc)
            for src_ip, events in saved_data["port_scan_events"].items():
                for ts_str, dst, port in events:
                    try:
                        ts = datetime.fromisoformat(ts_str)
                        if ts.tzinfo is None:
                            ts = ts.replace(tzinfo=timezone.utc)
                        agent.attack_detector.port_scan._events[src_ip].append((ts, dst, port))
                        loaded += 1
                    except Exception:
                        pass
        
        # SYN flood events
        if "syn_flood_events" in saved_data:
            for key, data in saved_data["syn_flood_events"].items():
                for ts_tuple in data.get("events", []):
                    try:
                        ts = datetime.fromisoformat(ts_tuple[0])
                        if ts.tzinfo is None:
                            ts = ts.replace(tzinfo=timezone.utc)
                        agent.attack_detector.syn_flood._events[key].append(ts)
                        loaded += 1
                    except Exception:
                        pass
        
        # Brute force events
        if "brute_force_events" in saved_data:
            for key, data in saved_data["brute_force_events"].items():
                for ts_tuple in data.get("events", []):
                    try:
                        ts = datetime.fromisoformat(ts_tuple[0])
                        if ts.tzinfo is None:
                            ts = ts.replace(tzinfo=timezone.utc)
                        agent.attack_detector.brute_force._events[key].append((ts, data.get("ip"), data.get("port")))
                        loaded += 1
                    except Exception:
                        pass
        
        # Probe events
        if "probe_events" in saved_data:
            for src_ip, events in saved_data["probe_events"].items():
                for ts_str, dst, port, flags in events:
                    try:
                        ts = datetime.fromisoformat(ts_str)
                        if ts.tzinfo is None:
                            ts = ts.replace(tzinfo=timezone.utc)
                        agent.attack_detector.probe._events[src_ip].append((ts, dst, port, flags))
                        loaded += 1
                    except Exception:
                        pass
        
        if loaded > 0:
            logger.info("Restored %d attack detector events", loaded)
    
    # ── NetworkClassifier persistence ────────────────────────────────
    
    def _save_network_classifier(self, agent) -> Dict:
        """Save network classifier data."""
        if not agent.network_classifier:
            return {}
        
        data = {}
        
        # Save IP tracking
        ip_data = {}
        for ip, info in agent.network_classifier.ip_data.items():
            if isinstance(info, dict):
                ip_data[ip] = {
                    "classification": info.get("classification", "UNKNOWN"),
                    "event_count": info.get("event_count", 0),
                    "first_seen": info.get("first_seen", ""),
                    "last_seen": info.get("last_seen", ""),
                    "src_events": info.get("src_events", 0),
                    "dst_events": info.get("dst_events", 0),
                }
        
        if ip_data:
            data["ip_data"] = ip_data
        
        # Save interface map if loaded from API
        if hasattr(agent.network_classifier, "_api_interface_map") and agent.network_classifier._api_interface_map:
            data["api_interface_map"] = {
                iface: cls for iface, cls in agent.network_classifier._api_interface_map.items()
            }
        
        # Save auto-discovered interfaces
        if hasattr(agent.network_classifier, "_auto_interface_map") and agent.network_classifier._auto_interface_map:
            data["auto_interface_map"] = {
                iface: cls for iface, cls in agent.network_classifier._auto_interface_map.items()
            }
        
        return data
    
    def _load_network_classifier(self, agent, saved_data: Dict) -> None:
        """Load and restore network classifier data."""
        if not agent.network_classifier:
            return
        
        loaded = 0
        
        # Restore IP data
        if "ip_data" in saved_data:
            for ip, info in saved_data["ip_data"].items():
                agent.network_classifier.ip_data[ip] = info
                loaded += 1
        
        # Restore API interface map (this persists API-loaded interfaces across restarts)
        if "api_interface_map" in saved_data:
            agent.network_classifier._api_interface_map = {
                iface: cls for iface, cls in saved_data["api_interface_map"].items()
            }
            logger.info("Restored API interface map from state")
        
        # Restore auto-discovered interface map
        if "auto_interface_map" in saved_data:
            agent.network_classifier._auto_interface_map = {
                iface: cls for iface, cls in saved_data["auto_interface_map"].items()
            }
            logger.info("Restored auto interface map from state")
        
        if loaded > 0:
            logger.info("Restored %d IP classifications", loaded)
    
    # ── GeoDetector persistence ──────────────────────────────────────
    
    def _save_geo_detector(self, agent) -> Dict:
        """Save geo detector data."""
        if not hasattr(agent, "geo_detector") or not agent.geo_detector:
            return {}
        
        data = {}
        
        # Save country events
        country_events = {}
        for cc, info in agent.geo_detector.country_events.items():
            if isinstance(info, dict):
                country_events[cc] = info
            else:
                country_events[cc] = {"count": int(info)}
        
        if country_events:
            data["country_events"] = country_events
        
        # Save normal countries
        if agent.geo_detector.normal_countries:
            data["normal_countries"] = list(agent.geo_detector.normal_countries)
        
        return data
    
    def _load_geo_detector(self, agent, saved_data: Dict) -> None:
        """Load and restore geo detector data."""
        if not hasattr(agent, "geo_detector") or not agent.geo_detector:
            return
        
        loaded = 0
        
        # Restore country events
        if "country_events" in saved_data:
            for cc, info in saved_data["country_events"].items():
                agent.geo_detector.country_events[cc] = info
                loaded += 1
        
        # Restore normal countries
        if "normal_countries" in saved_data:
            agent.geo_detector.normal_countries = set(saved_data["normal_countries"])
            loaded += 1
        
        if loaded > 0:
            logger.info("Restored geo detector data: %d entries", loaded)
    
    # ── ReverseDNS persistence ───────────────────────────────────────
    
    def _save_reverse_dns(self, agent) -> Dict:
        """Save reverse DNS cache."""
        if not hasattr(agent, "reverse_dns") or not agent.reverse_dns:
            return {}
        
        cache = agent.reverse_dns._cache
        if not cache:
            return {}
        
        data = {}
        for ip, (hostname, expiry) in cache.items():
            data[ip] = {
                "hostname": hostname,
                "expiry": expiry.isoformat() if hasattr(expiry, "isoformat") else expiry,
            }
        
        return data
    
    def _load_reverse_dns(self, agent, saved_data: Dict) -> None:
        """Load and restore reverse DNS cache."""
        if not hasattr(agent, "reverse_dns") or not agent.reverse_dns:
            return
        
        loaded = 0
        now = datetime.now(timezone.utc)
        
        for ip, info in saved_data.items():
            try:
                expiry_str = info["expiry"]
                expiry = datetime.fromisoformat(expiry_str)
                if expiry.tzinfo is None:
                    expiry = expiry.replace(tzinfo=timezone.utc)
                
                # Only load if not expired
                if expiry > now:
                    agent.reverse_dns._cache[ip] = (info["hostname"], expiry)
                    loaded += 1
            except Exception:
                pass
        
        if loaded > 0:
            logger.info("Restored %d reverse DNS cache entries", loaded)


def save_state(agent) -> None:
    """Convenience function to save agent state."""
    if hasattr(agent, "persistence"):
        agent.persistence.save(agent)


def load_state(agent) -> None:
    """Convenience function to load agent state."""
    if hasattr(agent, "persistence"):
        agent.persistence.load(agent)
