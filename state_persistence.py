"""
State persistence for OPNsense anomaly detection agent.

Saves and restores:
- StatisticalModel baselines (running stats: count, mean, m2, values)
- AttackDetector windows (port scan, SYN flood, brute force, probe events)
- NetworkClassifier IP tracking data
- GeoDetector country tracking
- Agent counters (event_count, anomaly_count, uptime_offset)
- ZenArmor classifier state
- IDS signature analyzer state
- Nginx monitor counters
- UniFi monitor client/device state caches

State is saved to a JSON file and loaded on startup.
Time-windowed state is pruned on load to remove stale data older than
each detector's window.
"""

import json
import logging
import time
from collections import defaultdict
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
                "version": 2,
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
                "system_log_classifier": self._save_system_log_classifier(agent),
                "zenarmor_classifier": self._save_zenarmor_classifier(agent),
                "ids_analyzer": self._save_ids_analyzer(agent),
                "nginx_monitor": self._save_nginx_monitor(agent),
                "unifi_monitor": self._save_unifi_monitor(agent),
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
            self._load_system_log_classifier(agent, state.get("system_log_classifier", {}))
            self._load_zenarmor_classifier(agent, state.get("zenarmor_classifier", {}))
            self._load_ids_analyzer(agent, state.get("ids_analyzer", {}))
            self._load_nginx_monitor(agent, state.get("nginx_monitor", {}))
            self._load_unifi_monitor(agent, state.get("unifi_monitor", {}))
            
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
        sf_cutoff = now - timedelta(seconds=agent.attack_detector.syn_flood.window_seconds)
        for dst_ip, events in agent.attack_detector.syn_flood._dst_events.items():
            kept = [(t.isoformat(), s) for t, s in events if t >= sf_cutoff]
            if kept:
                sf_events[dst_ip] = {"events": kept, "count": len(kept)}
        
        if sf_events:
            data["syn_flood_dst_events"] = sf_events
        
        # SYN flood source events (all sources hitting any dst)
        sf_src_events = []
        for t, dst in agent.attack_detector.syn_flood._src_events:
            if t >= sf_cutoff:
                sf_src_events.append((t.isoformat(), dst))
        if sf_src_events:
            data["syn_flood_src_events"] = sf_src_events
        
        # Brute force events
        bf_events = {}
        for key, events in agent.attack_detector.brute_force._sessions.items():
            window = agent.attack_detector.brute_force.window_seconds
            cutoff = now - timedelta(seconds=window)
            kept = [t.isoformat() for t in events if t >= cutoff]
            if kept:
                bf_events[key] = {"events": kept, "count": len(kept)}
        
        if bf_events:
            data["brute_force_events"] = bf_events
        
        # Probe events
        pr_events = {}
        for src_ip, events in agent.attack_detector.probe._scan_events.items():
            window = agent.attack_detector.probe.window_seconds
            cutoff = now - timedelta(seconds=window)
            kept = [(t.isoformat(), flags) for t, flags in events if t >= cutoff]
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
        if "syn_flood_dst_events" in saved_data:
            for dst_ip, data in saved_data["syn_flood_dst_events"].items():
                for ts_tuple in data.get("events", []):
                    try:
                        ts = datetime.fromisoformat(ts_tuple[0])
                        if ts.tzinfo is None:
                            ts = ts.replace(tzinfo=timezone.utc)
                        agent.attack_detector.syn_flood._dst_events[dst_ip].append((ts, ts_tuple[1]))
                        loaded += 1
                    except Exception:
                        pass
        
        if "syn_flood_src_events" in saved_data:
            for ts_tuple in saved_data["syn_flood_src_events"]:
                try:
                    ts = datetime.fromisoformat(ts_tuple[0])
                    if ts.tzinfo is None:
                        ts = ts.replace(tzinfo=timezone.utc)
                    agent.attack_detector.syn_flood._src_events.append((ts, ts_tuple[1]))
                    loaded += 1
                except Exception:
                    pass
        
        # Brute force events
        if "brute_force_events" in saved_data:
            for key_str, data in saved_data["brute_force_events"].items():
                try:
                    key = tuple(json.loads(key_str))
                except Exception:
                    continue
                for ts_str in data.get("events", []):
                    try:
                        ts = datetime.fromisoformat(ts_str)
                        if ts.tzinfo is None:
                            ts = ts.replace(tzinfo=timezone.utc)
                        agent.attack_detector.brute_force._sessions[key].append(ts)
                        loaded += 1
                    except Exception:
                        pass
        
        # Probe events
        if "probe_events" in saved_data:
            for src_ip, events in saved_data["probe_events"].items():
                for ts_str, flags in events:
                    try:
                        ts = datetime.fromisoformat(ts_str)
                        if ts.tzinfo is None:
                            ts = ts.replace(tzinfo=timezone.utc)
                        agent.attack_detector.probe._scan_events[src_ip].append((ts, flags))
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
        
        # Save IP tracking — use actual record keys from network_classifier.py
        ip_data = {}
        for ip, info in agent.network_classifier.wan_ips.items():
            if isinstance(info, dict):
                ip_data[ip] = {
                    "count": info.get("count", 0),
                    "interfaces": list(info.get("interfaces", set())),
                    "dst_ports": list(info.get("dst_ports", set())),
                    "src_ips": list(info.get("src_ips", set())),
                    "dst_ips": list(info.get("dst_ips", set())),
                    "protocols": list(info.get("protocols", set())),
                    "actions": dict(info.get("actions", {})),
                    "category": "WAN",
                }
        for ip, info in agent.network_classifier.lan_ips_auto.items():
            if isinstance(info, dict):
                ip_data[ip] = {
                    "count": info.get("count", 0),
                    "interfaces": list(info.get("interfaces", set())),
                    "dst_ports": list(info.get("dst_ports", set())),
                    "src_ips": list(info.get("src_ips", set())),
                    "dst_ips": list(info.get("dst_ips", set())),
                    "protocols": list(info.get("protocols", set())),
                    "actions": dict(info.get("actions", {})),
                    "category": "LAN",
                }
        for ip, info in agent.network_classifier.vpn_ips_auto.items():
            if isinstance(info, dict):
                ip_data[ip] = {
                    "count": info.get("count", 0),
                    "interfaces": list(info.get("interfaces", set())),
                    "dst_ports": list(info.get("dst_ports", set())),
                    "src_ips": list(info.get("src_ips", set())),
                    "dst_ips": list(info.get("dst_ips", set())),
                    "protocols": list(info.get("protocols", set())),
                    "actions": dict(info.get("actions", {})),
                    "category": "VPN",
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
        
        # Restore API interface map first (so classification works for IP loading)
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
        
        # Restore IP data — reconstruct sets and defaultdicts from saved lists
        if "ip_data" in saved_data:
            for ip, info in saved_data["ip_data"].items():
                category = info.get("category", "UNKNOWN")
                record = {
                    "count": info.get("count", 0),
                    "interfaces": set(info.get("interfaces", [])),
                    "dst_ports": set(info.get("dst_ports", [])),
                    "src_ips": set(info.get("src_ips", [])),
                    "dst_ips": set(info.get("dst_ips", [])),
                    "protocols": set(info.get("protocols", [])),
                    "actions": defaultdict(int, dict(info.get("actions", {}))),
                }
                if category == "WAN":
                    agent.network_classifier.wan_ips[ip] = record
                elif category == "LAN":
                    agent.network_classifier.lan_ips_auto[ip] = record
                elif category == "VPN":
                    agent.network_classifier.vpn_ips_auto[ip] = record
                else:
                    agent.network_classifier.wan_ips[ip] = record
                loaded += 1
        
        if loaded > 0:
            logger.info("Restored %d IP classifications", loaded)
    
    # ── SystemLogClassifier persistence ──────────────────────────────
    
    def _save_system_log_classifier(self, agent) -> Dict:
        """Save system log classifier data."""
        if not hasattr(agent, "system_log_classifier") or not agent.system_log_classifier:
            return {}
        
        data = {}
        slog = agent.system_log_classifier
        
        # Save service profiles
        service_data = {}
        for name, profile in slog.service_profiles.items():
            service_data[name] = {
                "service": profile.service,
                "action_counts": dict(profile.action_counts),
                "total_events": profile.total_events,
                "unique_src_ips": len(profile.src_ips),
                "unique_dst_ips": len(profile.dst_ips),
                "hourly_counts": dict(profile.hourly_counts),
                "first_seen": profile.first_seen.isoformat() if profile.first_seen else None,
                "last_seen": profile.last_seen.isoformat() if profile.last_seen else None,
            }
        
        if service_data:
            data["services"] = service_data
        
        # Save classifier-level counters
        data["total_events"] = slog.total_events
        
        # Save top services and log levels
        if slog.events_by_service:
            data["events_by_service"] = dict(slog.events_by_service.most_common(100))
        if slog.events_by_level:
            data["events_by_level"] = dict(slog.events_by_level.most_common())
        if slog._new_services_seen:
            data["new_services"] = list(slog._new_services_seen)
        
        return data
    
    def _load_system_log_classifier(self, agent, saved_data: Dict) -> None:
        """Load and restore system log classifier data."""
        if not hasattr(agent, "system_log_classifier") or not agent.system_log_classifier:
            return
        
        from collections import Counter
        from system_log_classifier import ServiceProfile
        
        slog = agent.system_log_classifier
        
        loaded = 0
        
        # Restore service profiles
        if "services" in saved_data:
            for name, data in saved_data["services"].items():
                try:
                    from datetime import datetime, timezone
                    profile = ServiceProfile(service=data["service"])
                    profile.action_counts = Counter(data.get("action_counts", {}))
                    profile.total_events = data.get("total_events", 0)
                    profile.hourly_counts = Counter(data.get("hourly_counts", {}))
                    if data.get("first_seen"):
                        ts = datetime.fromisoformat(data["first_seen"])
                        if ts.tzinfo is None:
                            ts = ts.replace(tzinfo=timezone.utc)
                        profile.first_seen = ts
                    if data.get("last_seen"):
                        ts = datetime.fromisoformat(data["last_seen"])
                        if ts.tzinfo is None:
                            ts = ts.replace(tzinfo=timezone.utc)
                        profile.last_seen = ts
                    
                    slog.service_profiles[name] = profile
                    loaded += 1
                except Exception as e:
                    logger.warning("Failed to restore service profile '%s': %s", name, e)
        
        if "events_by_service" in saved_data:
            slog.events_by_service = Counter(saved_data["events_by_service"])
        if "events_by_level" in saved_data:
            slog.events_by_level = Counter(saved_data["events_by_level"])
        if "new_services" in saved_data:
            slog._new_services_seen = set(saved_data["new_services"])
        if "total_events" in saved_data:
            slog.total_events = saved_data["total_events"]
        
        if loaded > 0:
            logger.info("Restored %d system log service profiles", loaded)
    
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
    
    # ── ZenArmorClassifier persistence ───────────────────────────────
    
    def _save_zenarmor_classifier(self, agent) -> Dict:
        """Save ZenArmor policy classifier data."""
        if not hasattr(agent, "zenarmor_classifier") or not agent.zenarmor_classifier:
            return {}
        
        zac = agent.zenarmor_classifier
        data = {}
        
        # Save policy profiles
        policies = {}
        for name, profile in zac.policies.items():
            policies[name] = {
                "name": profile.name,
                "actions": dict(profile.actions),
                "total_events": profile.total_events,
                "first_seen": profile.first_seen.isoformat() if profile.first_seen else None,
                "last_seen": profile.last_seen.isoformat() if profile.last_seen else None,
                "action_history": profile._action_history,
            }
        
        if policies:
            data["policies"] = policies
        
        # Save classifier-level counters
        data["total_events"] = zac.total_events
        data["events_with_policy"] = zac.events_with_policy
        data["events_without_policy"] = zac.events_without_policy
        
        return data
    
    def _load_zenarmor_classifier(self, agent, saved_data: Dict) -> None:
        """Load and restore ZenArmor classifier data."""
        if not hasattr(agent, "zenarmor_classifier") or not agent.zenarmor_classifier:
            return
        
        zac = agent.zenarmor_classifier
        loaded = 0
        
        # Restore policy profiles
        if "policies" in saved_data:
            for name, pdata in saved_data["policies"].items():
                try:
                    from zenarmor_classifier import ZenArmorPolicy
                    from collections import Counter
                    from datetime import datetime, timezone
                    
                    profile = ZenArmorPolicy(
                        name=pdata["name"],
                        total_events=pdata.get("total_events", 0),
                    )
                    profile.actions = Counter(pdata.get("actions", {}))
                    if pdata.get("first_seen"):
                        ts = datetime.fromisoformat(pdata["first_seen"])
                        if ts.tzinfo is None:
                            ts = ts.replace(tzinfo=timezone.utc)
                        profile.first_seen = ts
                    if pdata.get("last_seen"):
                        ts = datetime.fromisoformat(pdata["last_seen"])
                        if ts.tzinfo is None:
                            ts = ts.replace(tzinfo=timezone.utc)
                        profile.last_seen = ts
                    profile._action_history = pdata.get("action_history", [])
                    
                    zac.policies[name] = profile
                    loaded += 1
                except Exception as e:
                    logger.warning("Failed to restore ZenArmor policy '%s': %s", name, e)
        
        if "total_events" in saved_data:
            zac.total_events = saved_data["total_events"]
        if "events_with_policy" in saved_data:
            zac.events_with_policy = saved_data["events_with_policy"]
        if "events_without_policy" in saved_data:
            zac.events_without_policy = saved_data["events_without_policy"]
        
        if loaded > 0:
            logger.info("Restored %d ZenArmor policies", loaded)
    
    # ── IDSSignatureAnalyzer persistence ─────────────────────────────
    
    def _save_ids_analyzer(self, agent) -> Dict:
        """Save IDS signature analyzer data."""
        if not hasattr(agent, "ids_analyzer") or not agent.ids_analyzer:
            return {}
        
        ids = agent.ids_analyzer
        data = {}
        
        # Save signature profiles
        signatures = {}
        for name, profile in ids.signatures.items():
            signatures[name] = {
                "name": profile.name,
                "priority": profile.priority,
                "trigger_count": profile.trigger_count,
                "first_seen": profile.first_seen.isoformat() if profile.first_seen else None,
                "last_seen": profile.last_seen.isoformat() if profile.last_seen else None,
                "trigger_history": profile._trigger_history,
            }
        
        if signatures:
            data["signatures"] = signatures
        
        # Save analyzer-level counters
        data["total_events"] = ids.total_events
        data["events_with_signature"] = ids.events_with_signature
        data["events_without_signature"] = ids.events_without_signature
        
        return data
    
    def _load_ids_analyzer(self, agent, saved_data: Dict) -> None:
        """Load and restore IDS signature analyzer data."""
        if not hasattr(agent, "ids_analyzer") or not agent.ids_analyzer:
            return
        
        ids = agent.ids_analyzer
        loaded = 0
        
        # Restore signature profiles
        if "signatures" in saved_data:
            for name, sdata in saved_data["signatures"].items():
                try:
                    from ids_signature_analyzer import IDSSignature
                    from datetime import datetime, timezone
                    
                    profile = IDSSignature(
                        name=sdata["name"],
                        priority=sdata.get("priority", 0),
                        trigger_count=sdata.get("trigger_count", 0),
                    )
                    if sdata.get("first_seen"):
                        ts = datetime.fromisoformat(sdata["first_seen"])
                        if ts.tzinfo is None:
                            ts = ts.replace(tzinfo=timezone.utc)
                        profile.first_seen = ts
                    if sdata.get("last_seen"):
                        ts = datetime.fromisoformat(sdata["last_seen"])
                        if ts.tzinfo is None:
                            ts = ts.replace(tzinfo=timezone.utc)
                        profile.last_seen = ts
                    profile._trigger_history = sdata.get("trigger_history", [])
                    
                    ids.signatures[name] = profile
                    loaded += 1
                except Exception as e:
                    logger.warning("Failed to restore IDS signature '%s': %s", name, e)
        
        if "total_events" in saved_data:
            ids.total_events = saved_data["total_events"]
        if "events_with_signature" in saved_data:
            ids.events_with_signature = saved_data["events_with_signature"]
        if "events_without_signature" in saved_data:
            ids.events_without_signature = saved_data["events_without_signature"]
        
        if loaded > 0:
            logger.info("Restored %d IDS signatures", loaded)
    
    # ── NginxMonitor persistence ─────────────────────────────────────
    
    def _save_nginx_monitor(self, agent) -> Dict:
        """Save nginx monitor data."""
        if not hasattr(agent, "nginx_monitor") or not agent.nginx_monitor:
            return {}
        
        ng = agent.nginx_monitor
        data = {}
        
        # Save aggregated counts (the per-IP time-series are transient windows)
        if ng.request_counts:
            data["request_counts"] = dict(ng.request_counts.most_common(200))
        if ng.ip_request_counts:
            data["ip_request_counts"] = dict(ng.ip_request_counts.most_common(200))
        if ng.status_counts:
            data["status_counts"] = dict(ng.status_counts)
        if ng.method_counts:
            data["method_counts"] = dict(ng.method_counts)
        
        return data
    
    def _load_nginx_monitor(self, agent, saved_data: Dict) -> None:
        """Load and restore nginx monitor data."""
        if not hasattr(agent, "nginx_monitor") or not agent.nginx_monitor:
            return
        
        from collections import Counter
        
        ng = agent.nginx_monitor
        loaded = 0
        
        if "request_counts" in saved_data:
            ng.request_counts = Counter(saved_data["request_counts"])
            loaded += 1
        if "ip_request_counts" in saved_data:
            ng.ip_request_counts = Counter(saved_data["ip_request_counts"])
            loaded += 1
        if "status_counts" in saved_data:
            ng.status_counts = Counter(saved_data["status_counts"])
            loaded += 1
        if "method_counts" in saved_data:
            ng.method_counts = Counter(saved_data["method_counts"])
            loaded += 1
        
        if loaded > 0:
            logger.info("Restored nginx monitor data: %d counters", loaded)
    
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

        # Include resolver stats
        try:
            data["_stats"] = agent.reverse_dns.get_stats()
        except Exception:
            pass

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

    # ── UniFiMonitor persistence ─────────────────────────────────────

    def _save_unifi_monitor(self, agent) -> Dict:
        """Save UniFi monitor state (client/device caches for delta detection)."""
        if not hasattr(agent, "unifi_monitor") or not agent.unifi_monitor:
            return {}

        uf = agent.unifi_monitor
        data = {}

        # Save client state cache (for delta detection on restart)
        if uf._prev_clients:
            data["prev_clients"] = dict(uf._prev_clients)
        if uf._prev_devices:
            data["prev_devices"] = dict(uf._prev_devices)
        if uf._client_roam_count:
            data["client_roam_count"] = dict(uf._client_roam_count)
        if uf._poll_count > 0:
            data["poll_count"] = uf._poll_count
        if uf._error_count > 0:
            data["error_count"] = uf._error_count

        return data

    def _load_unifi_monitor(self, agent, saved_data: Dict) -> None:
        """Load and restore UniFi monitor state."""
        if not hasattr(agent, "unifi_monitor") or not agent.unifi_monitor:
            return

        uf = agent.unifi_monitor
        loaded = 0

        if "prev_clients" in saved_data:
            uf._prev_clients = saved_data["prev_clients"]
            loaded += 1
        if "prev_devices" in saved_data:
            uf._prev_devices = saved_data["prev_devices"]
            loaded += 1
        if "client_roam_count" in saved_data:
            uf._client_roam_count = defaultdict(int, saved_data["client_roam_count"])
            loaded += 1
        if "poll_count" in saved_data:
            uf._poll_count = saved_data["poll_count"]
            loaded += 1
        if "error_count" in saved_data:
            uf._error_count = saved_data["error_count"]
            loaded += 1

        if loaded > 0:
            logger.info("Restored unifi monitor data: %d items", loaded)


def save_state(agent) -> None:
    """Convenience function to save agent state."""
    if hasattr(agent, "persistence"):
        agent.persistence.save(agent)


def load_state(agent) -> None:
    """Convenience function to load agent state."""
    if hasattr(agent, "persistence"):
        agent.persistence.load(agent)
