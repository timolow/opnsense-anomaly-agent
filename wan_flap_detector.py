"""WAN Gateway flap detection.

Monitors OPNsense gateway states and detects flapping
(when gateways go up/down repeatedly), sending Discord alerts.
"""

import os
import time
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)


class WANFlapDetector:
    """Detects WAN gateway flapping by monitoring gateway states over time."""
    
    def __init__(self):
        """Initialize with flap detection parameters."""
        self.gateway_states: Dict[str, Dict[str, Any]] = {}
        self.last_flap_alert: Dict[str, float] = {}  # gateway -> last alert timestamp
        self.flap_alert_cooldown = int(os.getenv("WAN_FLAP_ALERT_COOLDOWN", "300"))  # 5 minutes
        self.flap_threshold = int(os.getenv("WAN_FLAP_THRESHOLD", "3"))  # alerts per window
        
        # Flap tracking per gateway
        # Key: gateway_name, Value: {"state": "up"/"down", "last_change": timestamp, "flap_count": int, "history": [(timestamp, state), ...]}
        self._flap_history: Dict[str, Dict] = {}
        
        logger.info("WANFlapDetector: initialized (threshold=%d, cooldown=%ds)", 
                   self.flap_threshold, self.flap_alert_cooldown)
    
    def check_gateway_state(self, gateway_name: str, old_state: str, new_state: str) -> Optional[Dict[str, Any]]:
        """Check if a gateway state change indicates flapping.
        
        Args:
            gateway_name: Gateway/interface name
            old_state: Previous state ('up' or 'down')
            new_state: Current state ('up' or 'down')
            
        Returns:
            Alert dict if flapping detected, None otherwise
        """
        if old_state == new_state:
            return None  # No state change
        
        now = time.time()
        
        # Initialize tracking if new gateway
        if gateway_name not in self._flap_history:
            self._flap_history[gateway_name] = {
                "state": old_state,
                "last_change": now,
                "flap_count": 0,
                "history": [(now, old_state)],
                "last_alert": 0,
            }
        
        history = self._flap_history[gateway_name]
        
        # Record state change
        history["state"] = new_state
        history["last_change"] = now
        history["history"].append((now, new_state))
        
        # Keep only last 24 hours of history
        cutoff = now - 86400
        history["history"] = [(ts, st) for ts, st in history["history"] if ts > cutoff]
        
        # Count flaps (state changes) in the last hour
        one_hour_ago = now - 3600
        recent_changes = sum(1 for ts, _ in history["history"] if ts > one_hour_ago)
        
        # Update flap count (flaps = state changes)
        history["flap_count"] = recent_changes - 1  # First change isn't a flap
        
        # Check if this is a flap alert condition
        if history["flap_count"] >= self.flap_threshold:
            # Check cooldown
            if now - history["last_alert"] < self.flap_alert_cooldown:
                return None
            
            # Send alert
            alert = self._create_flap_alert(gateway_name, history)
            history["last_alert"] = now
            return alert
        
        logger.debug("WANFlapDetector: %s state changed %s -> %s (flaps in 1h: %d)",
                    gateway_name, old_state, new_state, history["flap_count"])
        return None
    
    def _create_flap_alert(self, gateway_name: str, history: Dict) -> Dict[str, Any]:
        """Create a flap alert dictionary."""
        flaps = history["flap_count"]
        severity = "CRITICAL" if flaps >= 5 else "WARNING"
        
        return {
            "type": "WAN_FLAP",
            "severity": severity,
            "gateway": gateway_name,
            "description": f"WAN gateway '{gateway_name}' flapped {flaps} times in last hour",
            "flap_count": flaps,
            "current_state": history["state"],
            "last_change": history["last_change"],
        }
    
    def get_flap_status(self) -> Dict[str, Any]:
        """Get current flap detection status for all gateways."""
        status = {}
        for gw, history in self._flap_history.items():
            flaps_1h = sum(1 for ts, _ in history["history"] if ts > time.time() - 3600) - 1
            status[gw] = {
                "current_state": history["state"],
                "flaps_1h": max(0, flaps_1h),
                "total_changes": len(history["history"]),
                "last_change": history["last_change"],
            }
        return status
    
    def get_recent_flaps(self, hours: int = 24) -> list:
        """Get recent flap events."""
        cutoff = time.time() - (hours * 3600)
        flaps = []
        for gw, history in self._flap_history.items():
            for i in range(1, len(history["history"])):
                ts, state = history["history"][i]
                prev_ts, prev_state = history["history"][i-1]
                if ts > cutoff and prev_state != state:
                    flaps.append({
                        "gateway": gw,
                        "time": ts,
                        "old_state": prev_state,
                        "new_state": state,
                    })
        flaps.sort(key=lambda x: x["time"], reverse=True)
        return flaps[:50]  # Return most recent 50
