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
        fields = [
            {'name': 'Severity', 'value': severity, 'inline': True},
            {'name': 'Target', 'value': attack.get('dst_ip', 'N/A'), 'inline': True},
            {'name': 'Scanner', 'value': attack.get('src_ip', 'N/A'), 'inline': True},
            {'name': 'Scan Type', 'value': detail.get('scan_type', 'unknown'), 'inline': True},
            {'name': 'Ports Scanned', 'value': str(len(detail.get('ports', []))), 'inline': True},
            {'name': 'Scanned Ports', 'value': ', '.join(str(p) for p in detail.get('ports', [])[:10]) or 'N/A', 'inline': False},
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
            {'name': 'Service', 'value': f"Port {attack.get('dport', 'N/A')}", 'inline': True},
            {'name': 'Attempts', 'value': str(detail.get('attempts', 0)), 'inline': True},
            {'name': 'Window', 'value': f"{detail.get('window_seconds', 0)}s", 'inline': True},
        ]
    elif attack_type == 'PROBE':
        title = "Network Probe"
        fields = [
            {'name': 'Severity', 'value': severity, 'inline': True},
            {'name': 'Target', 'value': attack.get('dst_ip', 'N/A'), 'inline': True},
            {'name': 'Prober', 'value': attack.get('src_ip', 'N/A'), 'inline': True},
            {'name': 'Probe Type', 'value': detail.get('probe_type', 'unknown'), 'inline': True},
            {'name': 'Signature', 'value': detail.get('signature', 'N/A')[:50] or 'N/A', 'inline': False},
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
    
    def _post(self, endpoint: str, data: Dict[str, Any]) -> bool:
        """POST to Discord API with bot token auth."""
        import requests
        url = f"{DISCORD_API}/{endpoint}"
        headers = {
            'Authorization': f'Bot {self.token}',
            'Content-Type': 'application/json',
        }
        try:
            resp = requests.post(url, json=data, headers=headers, timeout=10)
            if resp.status_code == 200 or resp.status_code == 204:
                logger.debug("Discord API %s %s", resp.status_code, endpoint)
                return True
            else:
                logger.error("Discord API error: %s %s", resp.status_code, resp.text[:200])
                return False
        except Exception as e:
            logger.error("Discord API request failed: %s", e)
            return False
    
    def send_alert(self, attack: Dict[str, Any]) -> bool:
        dedup_key = f"{attack.get('attack_type')}:{attack.get('src_ip', 'x')}:{attack.get('dst_ip', 'x')}"
        if not self.rate_limiter.should_alert(attack.get('attack_type'), dedup_key):
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
    
    def record_attack(self, attack: Dict[str, Any]):
        self._recent_attacks.append(attack)
        if len(self._recent_attacks) > self._max_attacks:
            self._recent_attacks = self._recent_attacks[-self._max_attacks:]


# ============================================================
# Agent.py compatibility wrapper
# ============================================================


class DiscordBot:
    """Wrapper around DiscordClient providing the DiscordBot interface."""
    
    def __init__(self, config):
        self.config = config
        self._client = None
        self._running = False
        self._command_handler = CommandHandler()
    
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
    
    def start_bot(self):
        client = self._get_client()
        if client:
            self._running = True
            # Verify bot token works
            client.test_connection()
            logger.info("Discord bot enabled (bot API mode)")
        else:
            logger.warning("Discord token or channel not configured; alerts disabled")
    
    def stop(self):
        self._running = False
    
    def handle_command(self, command: str, args: str = '') -> CommandResult:
        return self._command_handler.handle_command(command, args)
    
    def record_attack(self, attack: Dict[str, Any]):
        self._command_handler.record_attack(attack)
