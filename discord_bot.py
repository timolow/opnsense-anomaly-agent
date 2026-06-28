"""
Discord bot for OPNsense anomaly detection agent.

Provides rate-limited alerting to Discord with rich embeds per
attack type. Uses Discord REST API with bot token for reliable
message delivery.
"""

import os
import time
import logging
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


# ============================================================
# Rate limiter
# ============================================================


class RateLimiter:
    """Per-signal rate limiter and dedup tracker."""
    
    def __init__(self, interval: int = 60, dedup_window: int = 300):
        self.interval = interval
        self.dedup_window = dedup_window
        self._last_alert: Dict[str, float] = {}
        self._dedup_keys: Dict[str, float] = {}
    
    def should_alert(self, signal: str, dedup_key: Optional[str] = None) -> bool:
        now = time.time()
        last = self._last_alert.get(signal, 0)
        if now - last < self.interval:
            return False
        if dedup_key and dedup_key in self._dedup_keys:
            if time.time() - self._dedup_keys[dedup_key] < self.dedup_window:
                return False
        self._last_alert[signal] = now
        if dedup_key:
            self._dedup_keys[dedup_key] = now
            cutoff = now - self.dedup_window
            self._dedup_keys = {k: v for k, v in self._dedup_keys.items() if v >= cutoff}
        return True
    
    def cleanup_dedup(self):
        now = time.time()
        cutoff = now - self.dedup_window
        self._dedup_keys = {k: v for k, v in self._dedup_keys.items() if v >= cutoff}


class CommandRateLimiter:
    """Per-user rate limiter for Discord chat commands.
    
    Uses a sliding window to track command timestamps per user ID.
    Default: 5 commands per 60-second window.
    """
    
    def __init__(self, max_commands: int = 5, window_seconds: int = 60):
        self.max_commands = max_commands
        self.window_seconds = window_seconds
        self._user_timestamps: Dict[str, List[float]] = {}
    
    def is_allowed(self, user_id: str) -> bool:
        """Check whether the user can issue another command now.
        
        Returns True if allowed, False if rate limited.
        When True, records the timestamp for future enforcement.
        """
        now = time.time()
        cutoff = now - self.window_seconds
        
        # Clean stale entries for this user
        timestamps = self._user_timestamps.get(user_id, [])
        timestamps = [ts for ts in timestamps if ts > cutoff]
        
        if len(timestamps) >= self.max_commands:
            # Rate limited — don't record
            self._user_timestamps[user_id] = timestamps
            return False
        
        # Allowed — record timestamp
        timestamps.append(now)
        self._user_timestamps[user_id] = timestamps
        
        # Periodic cleanup of empty user entries to prevent unbounded growth
        if len(self._user_timestamps) > 1000:
            self._cleanup()
        
        return True
    
    def remaining(self, user_id: str) -> int:
        """Return how many commands the user has left in the current window."""
        now = time.time()
        cutoff = now - self.window_seconds
        timestamps = self._user_timestamps.get(user_id, [])
        active = [ts for ts in timestamps if ts > cutoff]
        return max(0, self.max_commands - len(active))
    
    def reset(self, user_id: str):
        """Reset the rate limit for a specific user (admin override)."""
        self._user_timestamps.pop(user_id, None)
    
    def _cleanup(self):
        """Remove all stale entries to prevent memory growth."""
        now = time.time()
        cutoff = now - self.window_seconds
        self._user_timestamps = {
            uid: [ts for ts in timestamps if ts > cutoff]
            for uid, timestamps in self._user_timestamps.items()
        }
        # Remove users with no active entries
        self._user_timestamps = {
            uid: ts for uid, ts in self._user_timestamps.items() if ts
        }


# ============================================================
# Alert embed generator
# ============================================================


@dataclass
class AlertEmbed:
    """Represents a Discord embed for an alert."""
    title: str
    description: str
    color: int
    fields: List[Dict[str, str]] = field(default_factory=list)
    timestamp: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'title': self.title,
            'description': self.description,
            'color': self.color,
            'timestamp': self.timestamp or datetime.now(timezone.utc).isoformat(),
            'fields': self.fields,
        }


def severity_color(severity: str) -> int:
    colors = {
        'CRITICAL': 0xFF0000,
        'HIGH': 0xFF6600,
        'MEDIUM': 0xFFAA00,
        'LOW': 0x00AACC,
        'INFO': 0x6699CC,
    }
    return colors.get(severity.upper(), 0x6699CC)


def generate_attack_embed(attack: Dict[str, Any]) -> AlertEmbed:
    attack_type = attack.get('attack_type', 'UNKNOWN')
    severity = attack.get('severity', 'LOW')
    detail = attack.get('detail', {})
    timestamp = attack.get('timestamp', datetime.now(timezone.utc))
    
    if isinstance(timestamp, str):
        ts = timestamp
    else:
        ts = timestamp.isoformat() if timestamp else datetime.now(timezone.utc).isoformat()
    
    fields = []
    description = attack.get('description', '')
    title = ''
    
    if attack_type == 'PORT_SCAN':
        title = "Port Scan Detected"
        port_list = detail.get('port_list', [])
        fields = [
            {'name': 'Severity', 'value': severity, 'inline': True},
            {'name': 'Target', 'value': attack.get('dst_ip', 'N/A'), 'inline': True},
            {'name': 'Scanner', 'value': attack.get('src_ip', 'N/A'), 'inline': True},
            {'name': 'Scan Type', 'value': detail.get('scan_subtype', detail.get('scan_type', 'unknown')), 'inline': True},
            {'name': 'Ports Scanned', 'value': str(len(port_list)), 'inline': True},
            {'name': 'Scanned Ports', 'value': ', '.join(str(p) for p in port_list[:10]) or 'N/A', 'inline': False},
            {'name': 'Protocol', 'value': attack.get('proto', 'N/A'), 'inline': True},
        ]
    elif attack_type == 'SYN_FLOOD':
        title = "SYN Flood Detected"
        fields = [
            {'name': 'Severity', 'value': severity, 'inline': True},
            {'name': 'Target', 'value': attack.get('dst_ip', 'N/A'), 'inline': True},
            {'name': 'Port', 'value': str(attack.get('dst_port', 'N/A')), 'inline': True},
            {'name': 'SYN Count', 'value': str(detail.get('syn_count', 0)), 'inline': True},
            {'name': 'Threshold', 'value': str(detail.get('threshold', 0)), 'inline': True},
            {'name': 'Window', 'value': f"{detail.get('window_seconds', 0)}s", 'inline': True},
            {'name': 'Top Sources', 'value': '\n'.join(f"• {ip}" for ip in detail.get('top_sources', [])[:5]) or 'N/A', 'inline': False},
        ]
    elif attack_type == 'BRUTE_FORCE':
        title = "Brute Force Attempt"
        fields = [
            {'name': 'Severity', 'value': severity, 'inline': True},
            {'name': 'Target', 'value': attack.get('dst_ip', 'N/A'), 'inline': True},
            {'name': 'Attacker', 'value': attack.get('src_ip', 'N/A'), 'inline': True},
            {'name': 'Service', 'value': f"Port {attack.get('dst_port', 'N/A')}", 'inline': True},
            {'name': 'Attempts', 'value': str(detail.get('attempt_count', 0)), 'inline': True},
            {'name': 'Window', 'value': f"{detail.get('window_seconds', 0)}s", 'inline': True},
        ]
    elif attack_type == 'PROBE':
        title = "Network Probe"
        # Build a human-readable signature from detail
        if 'flags' in detail:
            sig = detail['flags']
        elif 'icmp_count' in detail:
            sig = f"ICMP flood ({detail['icmp_count']} packets)"
        else:
            sig = 'N/A'
        fields = [
            {'name': 'Severity', 'value': severity, 'inline': True},
            {'name': 'Target', 'value': attack.get('dst_ip', 'N/A'), 'inline': True},
            {'name': 'Prober', 'value': attack.get('src_ip', 'N/A'), 'inline': True},
            {'name': 'Probe Type', 'value': detail.get('scan_subtype', 'unknown'), 'inline': True},
            {'name': 'Signature', 'value': sig[:50] or 'N/A', 'inline': False},
            {'name': 'Protocol', 'value': attack.get('proto', 'N/A'), 'inline': True},
        ]
    elif attack_type == 'SCAN':
        title = "Network Scan"
        fields = [
            {'name': 'Severity', 'value': severity, 'inline': True},
            {'name': 'Target', 'value': attack.get('dst_ip', 'N/A'), 'inline': True},
            {'name': 'Scanner', 'value': attack.get('src_ip', 'N/A'), 'inline': True},
            {'name': 'Scan Type', 'value': detail.get('scan_type', 'unknown'), 'inline': True},
            {'name': 'Hosts', 'value': str(detail.get('hosts_scanned', 0)), 'inline': True},
            {'name': 'Ports', 'value': str(detail.get('ports_scanned', 0)), 'inline': True},
        ]
    elif attack_type == 'STATISTICAL_ANOMALY':
        title = "Statistical Anomaly"
        fields = [
            {'name': 'Severity', 'value': severity, 'inline': True},
            {'name': 'Metric', 'value': detail.get('metric', 'N/A'), 'inline': True},
            {'name': 'Current', 'value': str(detail.get('current_value', 'N/A')), 'inline': True},
            {'name': 'Baseline Mean', 'value': str(detail.get('baseline_mean', 'N/A')), 'inline': True},
            {'name': 'Std Dev', 'value': str(detail.get('baseline_stddev', 'N/A')), 'inline': True},
            {'name': 'Z-Score', 'value': str(detail.get('z_score', 'N/A')), 'inline': True},
            {'name': 'Samples', 'value': str(detail.get('sample_count', 'N/A')), 'inline': True},
        ]
    else:
        title = attack_type
        fields = [
            {'name': 'Severity', 'value': severity, 'inline': True},
            {'name': 'Details', 'value': description[:500], 'inline': False},
        ]
        if attack.get('src_ip'):
            fields.insert(0, {'name': 'Source', 'value': attack['src_ip'], 'inline': True})
        if attack.get('dst_ip'):
            fields.insert(1, {'name': 'Destination', 'value': attack['dst_ip'], 'inline': True})
    
    return AlertEmbed(
        title=title,
        description=description,
        color=severity_color(severity),
        fields=fields,
        timestamp=ts,
    )


def anomaly_to_embed(anomaly: Dict[str, Any]) -> Optional[AlertEmbed]:
    if not anomaly:
        return None
    return generate_attack_embed(anomaly)


# ============================================================
# Discord bot client using REST API with bot token
# ============================================================


DISCORD_API = "https://discord.com/api/v10"


class DiscordClient:
    """Discord bot client using REST API with bot token.
    
    Uses the standard Discord REST API with Authorization: Bot <token>
    to send messages to a channel. Simple, no async/threading needed.
    """
    
    def __init__(self, token: str, channel_id: str):
        self.token = token
        self.channel_id = channel_id
        self.rate_limiter = RateLimiter(interval=60, dedup_window=300)
        self._test_result = None
    
    def _post(self, endpoint: str, data: Dict[str, Any], max_retries: int = 3) -> bool:
        """POST to Discord API with bot token auth and exponential backoff retry."""
        import requests
        url = f"{DISCORD_API}/{endpoint}"
        headers = {
            'Authorization': f'Bot {self.token}',
            'Content-Type': 'application/json',
        }
        last_error = None
        for attempt in range(max_retries + 1):
            try:
                resp = requests.post(url, json=data, headers=headers, timeout=10)
                if resp.status_code == 200 or resp.status_code == 204:
                    if attempt > 0:
                        logger.info("Discord API recovered after %d retries: %s", attempt, endpoint)
                    logger.debug("Discord API %s %s", resp.status_code, endpoint)
                    return True
                # Retry on rate limit (429) and server errors (5xx)
                if resp.status_code == 429:
                    retry_after = float(resp.headers.get('Retry-After', 2 ** attempt))
                    logger.warning("Discord rate limited; waiting %.1fs", retry_after)
                    time.sleep(retry_after)
                    continue
                if 500 <= resp.status_code < 600:
                    last_error = resp.text[:200]
                    wait = min(2 ** attempt * 1.5, 30)
                    logger.warning("Discord server error %s (attempt %d/%d); retrying in %.1fs", resp.status_code, attempt + 1, max_retries + 1, wait)
                    time.sleep(wait)
                    continue
                logger.error("Discord API error: %s %s", resp.status_code, resp.text[:200])
                return False
            except requests.exceptions.Timeout:
                last_error = f"timeout on attempt {attempt + 1}"
                wait = min(2 ** attempt * 1.5, 30)
                logger.warning("Discord API timeout (attempt %d/%d); retrying in %.1fs", attempt + 1, max_retries + 1, wait)
                time.sleep(wait)
            except requests.exceptions.ConnectionError as e:
                last_error = str(e)
                wait = min(2 ** attempt * 1.5, 30)
                logger.warning("Discord connection error (attempt %d/%d); retrying in %.1fs: %s", attempt + 1, max_retries + 1, wait, e)
                time.sleep(wait)
            except Exception as e:
                logger.error("Discord API request failed: %s", e)
                return False
        logger.error("Discord API exhausted %d retries for %s: %s", max_retries, endpoint, last_error)
        return False
    
    def send_alert(self, attack: Dict[str, Any]) -> bool:
        # Use 'type' or 'attack_type' for dedup (system log anomalies use 'type')
        signal = attack.get('attack_type') or attack.get('type') or 'UNKNOWN'
        dedup_key = f"{signal}:{attack.get('src_ip', 'x')}:{attack.get('dst_ip', 'x')}:{attack.get('service', '')}"
        if not self.rate_limiter.should_alert(signal, dedup_key):
            return False
        
        embed = anomaly_to_embed(attack)
        if not embed:
            return False
        
        payload = {
            'embeds': [embed.to_dict()],
            'username': 'OPNsense Alert Bot',
        }
        result = self._post(f'channels/{self.channel_id}/messages', payload)
        if result:
            logger.info("Discord alert sent for %s", attack.get('attack_type'))
        return result
    
    def send_message(self, message: str) -> bool:
        """Send a plain text message."""
        payload = {'content': message}
        return self._post(f'channels/{self.channel_id}/messages', payload)
    
    def test_connection(self) -> bool:
        """Test the bot token is valid by fetching current user."""
        import requests
        url = f"{DISCORD_API}/users/@me"
        headers = {
            'Authorization': f'Bot {self.token}',
            'Content-Type': 'application/json',
        }
        try:
            resp = requests.get(url, headers=headers, timeout=10)
            if resp.status_code == 200:
                user = resp.json()
                logger.info("Discord bot verified as %s (#%s)", user.get('username'), user.get('discriminator'))
                return True
            else:
                logger.error("Discord auth failed: %s %s", resp.status_code, resp.text[:200])
                return False
        except Exception as e:
            logger.error("Discord test connection failed: %s", e)
            return False


# ============================================================
# Chat command handler
# ============================================================


@dataclass
class CommandResult:
    content: str
    embed: Optional[AlertEmbed] = None
    
    def to_dict(self) -> Dict[str, Any]:
        result = {'content': self.content}
        if self.embed:
            result['embeds'] = [self.embed.to_dict()]
        return result


class CommandHandler:
    COMMANDS = {
        'stats': 'Show current anomaly detection statistics',
        'status': 'Show agent status and configuration',
        'attacks': 'Show recent detected attacks',
        'geo': 'Show geographic anomaly statistics',
        'feedback': 'Mark anomaly as true_positive/false_positive/dismissed',
        'thresholds': 'Show current detection thresholds',
        'metrics': 'Show threshold performance metrics',
        'tune': 'Trigger manual threshold tuning',
        'search': 'Search anomalies by IP, attack type, or description',
        'top-threats': 'Show top threat IPs ranked by threat score',
        'recent-alerts': 'Show recent anomaly alerts',
        'incident': 'View or transition an incident by ID',
        'incident-status': 'List active incidents with optional filters',
        'help': 'Show available commands',
    }
    
    def __init__(self, agent=None):
        self.agent = agent
        self._recent_attacks: List[Dict[str, Any]] = []
        self._max_attacks = 50
    
    def handle_command(self, command: str, args: str = '') -> CommandResult:
        cmd = command.lower().strip()
        if cmd == 'help':
            lines = ['**Available commands:**']
            for name, desc in self.COMMANDS.items():
                lines.append(f'`/{name}` — {desc}')
            return CommandResult(content='\n'.join(lines))
        elif cmd == 'stats':
            return self._cmd_stats()
        elif cmd == 'status':
            return self._cmd_status()
        elif cmd == 'attacks':
            return self._cmd_attacks()
        elif cmd == 'geo':
            return self._cmd_geo()
        elif cmd == 'feedback':
            return self._cmd_feedback(args)
        elif cmd == 'thresholds':
            return self._cmd_thresholds()
        elif cmd == 'metrics':
            return self._cmd_threshold_metrics()
        elif cmd == 'tune':
            return self._cmd_tune()
        elif cmd == 'search':
            return self._cmd_search(args)
        elif cmd == 'top-threats':
            return self._cmd_top_threats(args)
        elif cmd == 'recent-alerts':
            return self._cmd_recent_alerts(args)
        elif cmd == 'incident':
            return self._cmd_incident(args)
        elif cmd == 'incident-status':
            return self._cmd_incident_status(args)
        else:
            return CommandResult(content=f"Unknown command: `{cmd}`. Type `/help` for available commands.")
    
    def _cmd_stats(self) -> CommandResult:
        if not self.agent:
            return CommandResult(content="Agent not available.")
        stats = {}
        try:
            if hasattr(self.agent, 'get_stats'):
                stats = self.agent.get_stats()
        except Exception:
            pass
        if not stats:
            return CommandResult(content="No statistics available yet.")
        lines = ['**Anomaly Detection Statistics:**']
        for key, value in stats.items():
            if isinstance(value, dict):
                lines.append(f'**{key}:**')
                for k, v in value.items():
                    lines.append(f'  {k}: {v}')
            else:
                lines.append(f'**{key}:** {value}')
        return CommandResult(content='\n'.join(lines))
    
    def _cmd_status(self) -> CommandResult:
        if not self.agent:
            return CommandResult(content="Agent not available.")
        lines = ['**Agent Status:**']
        lines.append(f'Events processed: {getattr(self.agent, "event_count", "N/A")}')
        lines.append(f'Alerts sent: {getattr(self.agent, "alert_count", "N/A")}')
        lines.append(f'Attack types detected: {len(self._recent_attacks)}')
        return CommandResult(content='\n'.join(lines))
    
    def _cmd_attacks(self) -> CommandResult:
        if not self._recent_attacks:
            return CommandResult(content="No attacks detected yet.")
        lines = ['**Recent Attacks:**']
        for attack in self._recent_attacks[-10:]:
            ts = attack.get('timestamp', 'N/A')
            if hasattr(ts, 'isoformat'):
                ts = ts.isoformat()
            lines.append(
                f"- [{attack.get('severity', 'N/A')}] "
                f"{attack.get('attack_type', 'N/A')}: "
                f"{attack.get('description', 'N/A')[:60]}... ({ts})"
            )
        return CommandResult(content='\n'.join(lines))
    
    def _cmd_geo(self) -> CommandResult:
        if not self.agent or not hasattr(self.agent, 'geo_detector'):
            return CommandResult(content="Geo lookup not available.")
        try:
            geo_stats = self.agent.geo_detector.get_country_stats()
        except Exception:
            return CommandResult(content="Failed to get geo statistics.")
        lines = ['**Geographic Statistics:**']
        lines.append(f"Total countries: {geo_stats.get('total_countries', 0)}")
        lines.append(f"Normal countries: {len(geo_stats.get('normal_countries', []))}")
        lines.append(
            f"High-risk countries seen: "
            f"{', '.join(geo_stats.get('high_risk_seen', [])) or 'None'}"
        )
        top = geo_stats.get('top_countries', [])
        if top:
            lines.append('\n**Top source countries:**')
            for cc, count in top[:5]:
                lines.append(f"- {cc}: {count} events")
        return CommandResult(content='\n'.join(lines))
    
    def _cmd_feedback(self, args: str) -> CommandResult:
        """Handle /feedback <anomaly_id> <label> [<reason>]"""
        parts = args.strip().split(None, 2)
        if len(parts) < 2:
            return CommandResult(content="Usage: `/feedback <anomaly_id> <true_positive|false_positive|dismissed> [reason]`")
        
        try:
            anomaly_id = int(parts[0])
        except ValueError:
            return CommandResult(content=f"Invalid anomaly ID: `{parts[0]}`")
        
        label = parts[1].lower()
        if label not in ('true_positive', 'false_positive', 'dismissed'):
            return CommandResult(content="Label must be: `true_positive`, `false_positive`, or `dismissed`")
        
        reason = parts[2] if len(parts) > 2 else ""
        
        # Get the tuner from the agent
        tuner = getattr(self.agent, 'threshold_tuner', None)
        if not tuner:
            return CommandResult(content="Threshold tuner not available.")
        
        try:
            tuner.record_feedback(
                anomaly_id=anomaly_id,
                label=label,
                reason=reason,
                user_id="discord",
            )
            return CommandResult(content=f"Feedback recorded: anomaly #{anomaly_id} marked as **{label}**" +
                                     (f"\nReason: {reason}" if reason else ""))
        except Exception as e:
            return CommandResult(content=f"Failed to record feedback: {e}")
    
    def _cmd_thresholds(self) -> CommandResult:
        """Handle /thresholds — show current threshold values."""
        tuner = getattr(self.agent, 'threshold_tuner', None)
        if not tuner:
            return CommandResult(content="Threshold tuner not available.")
        
        thresholds = tuner.get_all_thresholds()
        lines = ['**Current Detection Thresholds:**']
        for name, value in sorted(thresholds.items()):
            # Format nicely
            display_name = name.replace('_', ' ').title()
            lines.append(f"- **{display_name}:** `{value:.2f}`")
        
        lines.append('\nUse `/feedback <id> <label>` to provide feedback for auto-tuning.')
        return CommandResult(content='\n'.join(lines))
    
    def _cmd_threshold_metrics(self) -> CommandResult:
        """Handle /metrics — show threshold performance metrics."""
        tuner = getattr(self.agent, 'threshold_tuner', None)
        if not tuner:
            return CommandResult(content="Threshold tuner not available.")
        
        metrics = tuner.get_metrics()
        if not metrics:
            return CommandResult(content="No metrics available yet.")
        
        lines = ['**Threshold Performance Metrics:**']
        for ttype, m in metrics.items():
            display_name = ttype.replace('_', ' ').title()
            lines.append(f"\n**{display_name}:**")
            lines.append(f"  Threshold: `{m.get('current_threshold', 'N/A'):.2f}`")
            lines.append(f"  FPR: {m.get('false_positive_rate', 0):.1%}")
            lines.append(f"  TPR: {m.get('true_positive_rate', 0):.1%}")
            lines.append(f"  F1: {m.get('f1_score', 0):.2f}")
            lines.append(f"  Samples: {m.get('sample_count', 0)}")
        
        return CommandResult(content='\n'.join(lines))
    
    def _cmd_tune(self) -> CommandResult:
        """Handle /tune — trigger manual threshold tuning."""
        tuner = getattr(self.agent, 'threshold_tuner', None)
        if not tuner:
            return CommandResult(content="Threshold tuner not available.")
        
        try:
            adjustments = tuner.tune()
            if not adjustments:
                return CommandResult(content="No adjustments needed — all thresholds within targets.")
            
            changed = [a for a in adjustments if a['old_value'] != a['new_value']]
            if not changed:
                return CommandResult(content="Tuning complete — all thresholds already optimal.")
            
            lines = ['**Threshold Auto-Tune Results:**']
            for a in changed:
                lines.append(
                    f"- **{a['type'].replace('_', ' ').title()}:** "
                    f"`{a['old_value']:.2f}` → `{a['new_value']:.2f}` "
                    f"({a.get('reason', '')})"
                )
            return CommandResult(content='\n'.join(lines))
        except Exception as e:
            return CommandResult(content=f"Tuning failed: {e}")
    
    def _cmd_search(self, args: str) -> CommandResult:
        """Handle /search <query> — search anomalies by IP, type, or description."""
        query = args.strip()
        if not query:
            return CommandResult(content="Usage: `/search <query>` — search anomalies by IP, attack type, or description.")
        
        db = getattr(self.agent, 'db', None)
        if not db:
            return CommandResult(content="Database not available.")
        
        try:
            results = db.search_anomalies(query, limit=10)
        except Exception as e:
            return CommandResult(content=f"Search failed: {e}")
        
        if not results:
            return CommandResult(content=f"No anomalies matching `{query}`.")
        
        # Build embed fields for each result
        fields = []
        for r in results:
            name = f"**{r.get('attack_type', 'UNKNOWN')}** [{r.get('severity', '?')}]"
            value_lines = []
            if r.get('src_ip'):
                value_lines.append(f"From: `{r['src_ip']}`")
            if r.get('dst_ip'):
                value_lines.append(f"To: `{r['dst_ip']}`")
            if r.get('dst_port'):
                value_lines.append(f"Port: `{r['dst_port']}`")
            if r.get('proto'):
                value_lines.append(f"Proto: `{r['proto']}`")
            value_lines.append(f"ID: #{r.get('id', '?')}")
            if r.get('created_at_str'):
                value_lines.append(f"Time: {r['created_at_str']}")
            desc = (r.get('description') or '')[:100]
            if desc:
                value_lines.append(f"Details: {desc}")
            value = '\n'.join(value_lines)
            # Truncate field name to 256 chars, value to 1024
            fields.append({'name': name[:256], 'value': value[:1024], 'inline': False})
        
        embed = AlertEmbed(
            title=f"Search results for \"{query}\" ({len(results)} found)",
            description=f"Matching anomalies for query: `{query}`",
            color=0x5865F2,  # Blurple
            fields=fields,
        )
        
        content = f"Found **{len(results)}** anomaly(ies) matching `{query}`"
        return CommandResult(content=content, embed=embed)
    
    def _cmd_top_threats(self, args: str) -> CommandResult:
        """Handle /top-threats [N] — show top N threat IPs by score."""
        limit = 10
        hours = 24
        parts = args.strip().split()
        if parts:
            try:
                limit = int(parts[0])
                if limit < 1 or limit > 50:
                    limit = 10
            except ValueError:
                pass
            if len(parts) > 1:
                try:
                    hours = int(parts[1])
                except ValueError:
                    pass
        
        db = getattr(self.agent, 'db', None)
        if not db:
            return CommandResult(content="Database not available.")
        
        try:
            results = db.get_top_threat_ips(limit=limit, hours=hours)
        except Exception as e:
            return CommandResult(content=f"Query failed: {e}")
        
        if not results:
            return CommandResult(content=f"No threat data in the last {hours}h.")
        
        # Build embed fields — one per IP
        fields = []
        for rank, r in enumerate(results, 1):
            ip = r.get('src_ip', 'unknown')
            score = r.get('threat_score', 0)
            total = r.get('total', 0)
            types = r.get('attack_types', 'N/A')
            severity_parts = []
            if r.get('critical_count', 0) > 0:
                severity_parts.append(f"🔴 {r['critical_count']} critical")
            if r.get('high_count', 0) > 0:
                severity_parts.append(f"🟠 {r['high_count']} high")
            if r.get('medium_count', 0) > 0:
                severity_parts.append(f"🟡 {r['medium_count']} medium")
            if r.get('low_count', 0) > 0:
                severity_parts.append(f"🔵 {r['low_count']} low")
            severity_str = ' | '.join(severity_parts) if severity_parts else 'no breakdown'
            
            name = f"#{rank} `{ip}` (score: {score})"
            value = f"Total: {total} anomalies\nTypes: {types}\n{severity_str}"
            fields.append({'name': name[:256], 'value': value[:1024], 'inline': False})
        
        embed = AlertEmbed(
            title=f"Top Threat IPs (last {hours}h)",
            description=f"Ranked by threat score (CRITICAL=10, HIGH=5, MEDIUM=2, LOW=1)",
            color=0xFF6600,  # Orange
            fields=fields,
        )
        
        content = f"Top **{len(results)}** threat IPs from the last **{hours}h**"
        return CommandResult(content=content, embed=embed)
    
    def _cmd_recent_alerts(self, args: str) -> CommandResult:
        """Handle /recent-alerts [N] — show recent anomaly alerts."""
        limit = 10
        parts = args.strip().split()
        if parts:
            try:
                limit = int(parts[0])
                if limit < 1 or limit > 50:
                    limit = 10
            except ValueError:
                pass
        
        db = getattr(self.agent, 'db', None)
        if not db:
            return CommandResult(content="Database not available.")
        
        try:
            results = db.get_recent_anomalies(limit=limit)
        except Exception as e:
            return CommandResult(content=f"Query failed: {e}")
        
        if not results:
            return CommandResult(content="No recent anomalies found.")
        
        # Build embed fields — one per alert
        fields = []
        for r in results:
            atype = r.get('attack_type', 'UNKNOWN')
            severity = r.get('severity', '?')
            icon = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🔵'}.get(severity, '⚪')
            detail_dict = r.get('detail') or {}
            
            value_lines = []
            if r.get('src_ip'):
                value_lines.append(f"Source: `{r['src_ip']}`")
            if r.get('dst_ip'):
                value_lines.append(f"Target: `{r['dst_ip']}`")
            if r.get('dst_port'):
                value_lines.append(f"Port: `{r['dst_port']}`")
            if r.get('proto'):
                value_lines.append(f"Proto: `{r['proto']}`")
            alert_status = "🔔 Sent" if r.get('discord_sent') else "📋 Logged"
            value_lines.append(f"Discord: {alert_status}")
            desc = (r.get('description') or '')[:150]
            if desc:
                value_lines.append(f"Desc: {desc}")
            
            name = f"{icon} **{atype}** [{severity}] (#{r.get('id', '?')})"
            value = '\n'.join(value_lines)
            fields.append({'name': name[:256], 'value': value[:1024], 'inline': False})
        
        embed = AlertEmbed(
            title=f"Recent Anomaly Alerts ({len(results)} shown)",
            description="Most recent anomalies detected by the agent",
            color=0xFFAA00,  # Amber
            fields=fields,
        )
        
        content = f"Showing **{len(results)}** most recent alerts"
        return CommandResult(content=content, embed=embed)
    
    def _cmd_incident(self, args: str) -> CommandResult:
        """Handle /incident <inc_id> [transition|feedback] [status|feedback_type] — View or act on an incident."""
        parts = args.strip().split()
        if not parts:
            return CommandResult(content="Usage: `/incident <inc_id> [action] [value]`\n\nActions:\n  (none) — View incident details\n  `transition <status>` — Transition to: investigating, confirmed, resolved\n  `feedback thumbs_up|thumbs_down` — Record feedback\n  `stats` — Show incident statistics")

        inc_id = parts[0]
        action = parts[1] if len(parts) > 1 else ""
        value = parts[2] if len(parts) > 2 else ""

        # Get the incident manager
        mgr = getattr(self.agent, 'incident_manager', None)
        if not mgr:
            return CommandResult(content="Incident manager not available.")

        if action == "transition":
            if not value:
                return CommandResult(content="Usage: `/incident <inc_id> transition <investigating|confirmed|resolved>`")
            success, message = mgr.transition(inc_id, value)
            status_icon = "✅" if success else "❌"
            return CommandResult(content=f"{status_icon} {message}")

        elif action == "feedback":
            if not value:
                return CommandResult(content="Usage: `/incident <inc_id> feedback <thumbs_up|thumbs_down>`")
            success, message = mgr.record_feedback(inc_id, value)
            status_icon = "✅" if success else "❌"
            return CommandResult(content=f"{status_icon} {message}")

        elif action == "stats":
            stats = mgr.get_stats()
            lines = ["**Incident Statistics:**"]
            for k, v in stats.items():
                lines.append(f"- **{k}:** {v}")
            return CommandResult(content="\n".join(lines))

        else:
            result = mgr.get_incident(inc_id)
            if result is None:
                return CommandResult(content=f"Incident not found: `{inc_id}`")

            # Build embed
            status_colors = {
                "new": 0x5865F2,  # Blurple
                "investigating": 0xFFAA00,  # Amber
                "confirmed": 0xFF6600,  # Orange
                "resolved": 0x00CC66,  # Green
            }

            fields = [
                {"name": "Status", "value": result["status"].upper(), "inline": True},
                {"name": "Severity", "value": result["severity"].upper(), "inline": True},
                {"name": "IP", "value": f"`{result['ip']}`", "inline": True},
                {"name": "Signals", "value": str(result["signal_count"]), "inline": True},
                {"name": "Feedback Score", "value": f"{result.get('feedback_score', 0):.2f} ({result.get('feedback_count', 0)} votes)", "inline": True},
            ]

            if result.get("signal_types"):
                fields.append({"name": "Signal Types", "value": ", ".join(result["signal_types"]), "inline": False})
            if result.get("description"):
                fields.append({"name": "Description", "value": result["description"][:1024], "inline": False})

            embed = AlertEmbed(
                title=f"Incident: {inc_id}",
                description=f"Group: {result.get('group_id', 'None')}",
                color=status_colors.get(result["status"], 0x6699CC),
                fields=fields,
            )

            return CommandResult(content=f"**{inc_id}** — {result['ip']}", embed=embed)

    def _cmd_incident_status(self, args: str) -> CommandResult:
        """Handle /incident-status [status] [severity] — List active incidents."""
        parts = args.strip().split()
        status_filter = None
        severity_filter = "low"

        for p in parts:
            if p in ("new", "investigating", "confirmed", "resolved"):
                status_filter = p
            elif p in ("low", "medium", "high", "critical"):
                severity_filter = p

        mgr = getattr(self.agent, 'incident_manager', None)
        if not mgr:
            return CommandResult(content="Incident manager not available.")

        incidents = mgr.get_incidents(
            status=status_filter,
            min_severity=severity_filter,
            limit=20,
        )

        if not incidents:
            filter_str = f" (status={status_filter or 'all'}, severity>={severity_filter})"
            return CommandResult(content=f"No incidents found{filter_str}.")

        # Build embed
        fields = []
        for inc in incidents:
            status_icon = {"new": "🆕", "investigating": "🔍", "confirmed": "✅", "resolved": "🏁"}.get(inc["status"], "⚪")
            sev_icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵"}.get(inc["severity"], "⚪")
            name = f"{status_icon} {sev_icon} **{inc['id']}** — {inc['ip']}"
            value_lines = [
                f"Severity: {inc['severity'].upper()}",
                f"Signals: {inc['signal_count']}",
                f"Group: {inc.get('group_id', 'None')}",
            ]
            if inc.get("description"):
                value_lines.append(f"{inc['description'][:200]}")
            fields.append({"name": name[:256], "value": "\n".join(value_lines), "inline": False})

        embed = AlertEmbed(
            title=f"Active Incidents ({len(incidents)} shown)",
            description=f"Filter: status={status_filter or 'all'}, min_severity={severity_filter}",
            color=0x5865F2,
            fields=fields,
        )

        content = f"**{len(incidents)}** active incidents"
        return CommandResult(content=content, embed=embed)
    
    def record_attack(self, attack: Dict[str, Any]):
        self._recent_attacks.append(attack)
        if len(self._recent_attacks) > self._max_attacks:
            self._recent_attacks = self._recent_attacks[-self._max_attacks:]

# ============================================================
# Discord bot with message listener (discord.py)
# ============================================================
#
# OPNsenseBot is defined as a factory function that creates the class
# dynamically inside a method where `discord` is already imported.
# This avoids a hard module-level dependency on discord.py — the REST
# alert client (DiscordClient) works fine without it.


class DiscordBot:
    """Discord bot that both sends alerts AND listens for chat commands.
    
    Includes automatic reconnection with exponential backoff: if the
    discord.py WebSocket disconnects or the bot thread dies, the bot
    reconnects automatically (initial 5s delay, up to 30s max).
    """
    
    # Reconnection config
    RECONNECT_BASE_DELAY = 1    # seconds before first reconnect attempt
    RECONNECT_MAX_DELAY = 60    # cap on backoff delay
    RECONNECT_MAX_COUNT = 10    # max reconnect attempts before giving up (0 = infinite)
    
    def __init__(self, config):
        self.config = config
        self._client = None
        self._running = False
        self._command_handler = CommandHandler()
        self._bot_client = None       # discord.py bot instance
        self._bot_thread = None       # thread running bot.run()
        self._reconnect_thread = None # thread watching for disconnects
        self._stop_event = None       # threading.Event for clean shutdown
        self._connect_count = 0       # how many times we've connected
        self._reconnect_count = 0     # how many reconnects so far
        # Per-user command rate limiter (5 commands/minute by default)
        self._command_rate_limiter = CommandRateLimiter(
            max_commands=5,
            window_seconds=60,
        )
    
    def _get_client(self):
        if not self._client and self.config.discord_token and self.config.discord_channel_id:
            self._client = DiscordClient(
                token=self.config.discord_token,
                channel_id=self.config.discord_channel_id,
            )
        return self._client
    
    def send_alert(self, attack, llm_analysis=None):
        client = self._get_client()
        if not client:
            logger.warning("Discord not configured; alerts disabled")
            return False
        try:
            return client.send_alert(attack)
        except Exception as e:
            logger.warning("Discord send_alert error: %s", e)
            return False
    
    def set_agent(self, agent):
        """Set the agent reference on the command handler so /status and other commands work."""
        self._command_handler.agent = agent

    def start_bot(self):
        client = self._get_client()
        if client:
            self._running = True
            self._stop_event = __import__('threading').Event()
            # Verify bot token works via REST
            client.test_connection()
            logger.info("Discord bot enabled (bot API mode)")
            # Start discord.py bot for message listening (with reconnection)
            self._start_bot_client()
        else:
            logger.warning("Discord token or channel not configured; alerts disabled")
    
    def _run_bot_once(self):
        """Start the discord.py bot client; runs until disconnect/error."""
        import discord
        
        class OPNsenseBot(discord.Client):
            """Discord bot client that listens for /commands and responds.
            
            Inherits from discord.Client with reconnect=False so we control
            reconnection ourselves via the reconnect watcher thread with
            explicit exponential backoff.
            """
            
            def __init__(self, bot_instance):
                intents = discord.Intents.default()
                intents.message_content = True
                super().__init__(intents=intents)
                self._bot_instance = bot_instance
            
            async def on_ready(self):
                user = self.user  # Always non-None by the time on_ready fires
                assert user is not None
                logger.info(
                    "Discord bot connected as %s (ID: %s)",
                    user.name, user.id,
                )
                
                # Register slash commands via REST API
                await self._register_slash_commands()
            
            async def _register_slash_commands(self):
                """Register slash commands with Discord via the API."""
                import requests as _requests
                cmd_url = f"{DISCORD_API}/applications/{self.user.id}/commands"
                headers = {
                    'Authorization': f'Bot {self._bot_instance.config.discord_token}',
                    'Content-Type': 'application/json',
                    'X-Audit-Log-Reason': 'Register OPNsense anomaly commands',
                }
                commands = [
                    {
                        'name': 'search',
                        'description': 'Search anomalies by IP, attack type, or description',
                        'options': [
                            {
                                'type': 3,  # STRING
                                'name': 'query',
                                'description': 'Search query (IP, attack type, or description)',
                                'required': True,
                            }
                        ],
                    },
                    {
                        'name': 'top-threats',
                        'description': 'Show top threat IPs ranked by threat score',
                        'options': [
                            {
                                'type': 4,  # INTEGER
                                'name': 'limit',
                                'description': 'Number of IPs to show (1-50, default: 10)',
                                'required': False,
                            },
                            {
                                'type': 4,  # INTEGER
                                'name': 'hours',
                                'description': 'Time window in hours (default: 24)',
                                'required': False,
                            }
                        ],
                    },
                    {
                        'name': 'recent-alerts',
                        'description': 'Show recent anomaly alerts',
                        'options': [
                            {
                                'type': 4,  # INTEGER
                                'name': 'limit',
                                'description': 'Number of alerts to show (1-50, default: 10)',
                                'required': False,
                            }
                        ],
                    },
                    {
                        'name': 'incident',
                        'description': 'View or transition an incident by ID',
                        'options': [
                            {
                                'type': 3,  # STRING
                                'name': 'incident_id',
                                'description': 'Incident ID (e.g. inc_abc123)',
                                'required': True,
                            },
                            {
                                'type': 3,  # STRING
                                'name': 'action',
                                'description': 'Action: transition, feedback, or stats',
                                'required': False,
                            },
                            {
                                'type': 3,  # STRING
                                'name': 'value',
                                'description': 'Value: status for transition, thumbs_up/thumbs_down for feedback',
                                'required': False,
                            }
                        ],
                    },
                    {
                        'name': 'incident-status',
                        'description': 'List active incidents with optional filters',
                        'options': [
                            {
                                'type': 3,  # STRING
                                'name': 'status',
                                'description': 'Filter by status (new, investigating, confirmed, resolved)',
                                'required': False,
                            },
                            {
                                'type': 3,  # STRING
                                'name': 'severity',
                                'description': 'Minimum severity (low, medium, high, critical)',
                                'required': False,
                            }
                        ],
                    },
                ]
                try:
                    resp = _requests.put(cmd_url, json=commands, headers=headers, timeout=10)
                    if resp.status_code == 200:
                        logger.info("Registered %d slash commands with Discord", len(commands))
                    else:
                        logger.warning(
                            "Failed to register slash commands: %s %s",
                            resp.status_code, resp.text[:200],
                        )
                except Exception as e:
                    logger.warning("Slash command registration failed: %s", e)
            
            async def on_interaction(self, interaction):
                """Handle slash command invocations."""
                # Acknowledge immediately (Discord requires response within 3s)
                if interaction.type == 2:  # APPLICATION_COMMAND
                    await interaction.respond(defer=True)
                    
                    # Rate limiting
                    user_id = str(interaction.user.id)
                    rate_limiter = self._bot_instance._command_rate_limiter
                    if not rate_limiter.is_allowed(user_id):
                        await interaction.followup.send(
                            f"⚠️ Rate limited — you've hit the command limit "
                            f"({rate_limiter.max_commands} commands per "
                            f"{rate_limiter.window_seconds}s). "
                            f"Try again shortly.",
                            ephemeral=True,
                        )
                        return
                    
                    # Extract command and args
                    cmd = interaction.data['name']
                    opts = {opt['name']: opt.get('value') for opt in interaction.data.get('options', [])}
                    
                    # Build args string for the command handler
                    args_parts = []
                    if cmd == 'search':
                        args_parts.append(str(opts.get('query', '')))
                    elif cmd == 'top-threats':
                        limit = opts.get('limit')
                        hours = opts.get('hours')
                        if limit is not None:
                            args_parts.append(str(limit))
                        if hours is not None:
                            args_parts.append(str(hours))
                    elif cmd == 'recent-alerts':
                        limit = opts.get('limit')
                        if limit is not None:
                            args_parts.append(str(limit))
                    args_str = ' '.join(args_parts)
                    
                    # Handle the command
                    result = self._bot_instance._command_handler.handle_command(cmd, args_str)
                    
                    # Send response with embed if present
                    send_kwargs: Dict[str, Any] = {}
                    if result.content:
                        send_kwargs['content'] = result.content
                    if result.embed:
                        import discord as _discord
                        embed_dict = result.embed.to_dict()
                        embed = _discord.Embed(
                            title=embed_dict.get('title', ''),
                            description=embed_dict.get('description', ''),
                            color=embed_dict.get('color', 0x5865F2),
                            timestamp=datetime.fromisoformat(embed_dict['timestamp']) if embed_dict.get('timestamp') else None,
                        )
                        for f in embed_dict.get('fields', []):
                            embed.add_field(
                                name=f['name'],
                                value=f['value'],
                                inline=f.get('inline', False),
                            )
                        send_kwargs['embed'] = embed
                    await interaction.followup.send(**send_kwargs)
            
            async def on_disconnect(self):
                """Called when the WebSocket disconnects — signal reconnector."""
                import sys as _sys
                exc_type, exc_val = None, None
                if _sys.exc_info()[0] is not None:
                    exc_type, exc_val = _sys.exc_info()[:2]
                if exc_type:
                    logger.warning(
                        "Discord disconnect with error: %s: %s",
                        exc_type.__name__, exc_val,
                    )
                else:
                    logger.warning(
                        "Discord WebSocket disconnected (no error — possible network flap)",
                    )
                # reconnect=False means run() exits here, so the watcher
                # picks up the dead thread and restarts with backoff.
            
            async def on_error(self, event_method, *args, **kwargs):
                """Catch-all error handler for discord.py events."""
                import sys as _sys
                logger.error(
                    "Discord error in %s: %s",
                    event_method, _sys.exc_info()[1],
                )
            
            async def on_message(self, message):
                # Ignore messages from the bot itself
                if message.author == self.user:
                    return
                
                # Only respond in the configured channel
                if str(message.channel.id) != self._bot_instance.config.discord_channel_id:
                    return
                
                # Strip leading slash and extract command
                content = message.content.strip()
                if content.startswith('/'):
                    content = content[1:]
                
                # Split command and args
                parts = content.split(None, 1)
                cmd = parts[0].lower() if parts else ''
                args = parts[1] if len(parts) > 1 else ''
                
                # Per-user rate limiting (protects expensive DB queries from spam)
                user_id = str(message.author.id)
                rate_limiter = self._bot_instance._command_rate_limiter
                if not rate_limiter.is_allowed(user_id):
                    remaining = rate_limiter.remaining(user_id)
                    await message.channel.send(
                        f"⚠️ Rate limited — you've hit the command limit "
                        f"({rate_limiter.max_commands} commands per "
                        f"{rate_limiter.window_seconds}s). "
                        f"Try again shortly."
                    )
                    logger.warning(
                        "Discord command rate limited: user=%s (%s)",
                        message.author.name, user_id,
                    )
                    return
                
                # Handle the command
                result = self._bot_instance._command_handler.handle_command(cmd, args)
                
                # Send response — include embed if the command returned one
                send_kwargs: Dict[str, Any] = {}
                if result.content:
                    send_kwargs['content'] = result.content
                if result.embed:
                    import discord as _discord
                    embed_dict = result.embed.to_dict()
                    embed = _discord.Embed(
                        title=embed_dict.get('title', ''),
                        description=embed_dict.get('description', ''),
                        color=embed_dict.get('color', 0x5865F2),
                        timestamp=datetime.fromisoformat(embed_dict['timestamp']) if embed_dict.get('timestamp') else None,
                    )
                    for f in embed_dict.get('fields', []):
                        embed.add_field(
                            name=f['name'],
                            value=f['value'],
                            inline=f.get('inline', False),
                        )
                    send_kwargs['embed'] = embed
                await message.channel.send(**send_kwargs)
        
        try:
            self._bot_client = OPNsenseBot(self)
            self._bot_client.run(self.config.discord_token)
        except (discord.errors.LoginFailure, discord.errors.PrivilegedIntentsRequired) as e:
            logger.error("Discord login failed (bad token or intents?): %s", e)
        except Exception as e:
            logger.error("Discord bot crashed: %s", e)
        finally:
            self._bot_client = None
            # Signal the reconnect watcher that the bot died
            if self._stop_event and not self._stop_event.is_set():
                logger.info("Discord bot thread exited — signaling reconnector")
    
    def _reconnect_watcher(self):
        """Watch the bot thread and restart with exponential backoff on disconnect."""
        while not self._stop_event.is_set():
            # Wait for the bot thread to die or stop signal
            if self._bot_thread and self._bot_thread.is_alive():
                self._bot_thread.join(timeout=1.0)
                continue  # still alive, keep watching
            
            if self._stop_event.is_set():
                break
            
            # Bot died — check reconnect limit
            if self.RECONNECT_MAX_COUNT and self._reconnect_count >= self.RECONNECT_MAX_COUNT:
                logger.error(
                    "Discord bot exceeded %d reconnect attempts; stopping",
                    self.RECONNECT_MAX_COUNT,
                )
                # Alert via REST API (works even when WebSocket is dead)
                client = self._get_client()
                if client:
                    client.send_message(
                        "⚠️ **Discord bot permanently disconnected** — exceeded "
                        f"{self.RECONNECT_MAX_COUNT} reconnect attempts. "
                        "Chat commands are unavailable until the agent restarts. "
                        "Alert delivery via REST API still works."
                    )
                break
            
            self._reconnect_count += 1
            delay = min(
                self.RECONNECT_BASE_DELAY * (2 ** (self._reconnect_count - 1)),
                self.RECONNECT_MAX_DELAY,
            )
            logger.info(
                "Discord bot disconnected — reconnecting in %.0fs (attempt %d)",
                delay, self._reconnect_count,
            )
            
            # Wait with interrupt check
            waited = self._stop_event.wait(timeout=delay)
            if waited:  # stop event was set during wait
                break
            
            logger.info("Reconnecting Discord bot (attempt %d)...", self._reconnect_count)
            self._connect_count += 1
            self._start_bot_thread()
    
    def _start_bot_thread(self):
        """Start the discord.py bot in a background thread."""
        from threading import Thread
        self._bot_thread = Thread(
            target=self._run_bot_once,
            daemon=True,
            name="discord-bot",
        )
        self._bot_thread.start()
        logger.info("Discord bot listener started (connection #%d)", self._connect_count)
    
    def _start_bot_client(self):
        """Start the discord.py bot with reconnection watcher."""
        try:
            import discord  # noqa: F401 — verify installed
            from threading import Thread
            
            self._connect_count += 1
            self._start_bot_thread()
            
            # Start the reconnect watcher thread
            self._reconnect_thread = Thread(
                target=self._reconnect_watcher,
                daemon=True,
                name="discord-reconnect",
            )
            self._reconnect_thread.start()
            logger.info("Discord reconnect watcher started")
            
        except ImportError:
            logger.warning("discord.py not installed; chat commands disabled (alerts still work)")
        except Exception as e:
            logger.error("Failed to start Discord bot client: %s", e)
    
    def stop(self):
        """Stop the bot and all background threads."""
        self._running = False
        if self._stop_event:
            self._stop_event.set()
        
        # Close the bot client
        if self._bot_client:
            try:
                import asyncio
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                loop.run_until_complete(self._bot_client.close())
                loop.close()
            except Exception as e:
                logger.warning("Error stopping Discord bot: %s", e)
        
        # Wait for threads to finish
        for thread in [self._reconnect_thread, self._bot_thread]:
            if thread and thread.is_alive():
                thread.join(timeout=5)
    
    def handle_command(self, command: str, args: str = '') -> CommandResult:
        return self._command_handler.handle_command(command, args)
    
    def record_attack(self, attack: Dict[str, Any]):
        self._command_handler.record_attack(attack)
