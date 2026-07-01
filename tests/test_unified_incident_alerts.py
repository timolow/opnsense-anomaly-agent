#!/usr/bin/env python3
"""
Tests for unified incident alert formatting in discord_bot.py.

Covers:
- send_incident_alert() with behavioral score, DNS, attack chain, recommended actions
- Deduplication within DEDUP_SECONDS
- /incident command IP-based lookup
- _recommend_actions() and _score_to_threat()
"""

import time
import unittest
from unittest.mock import MagicMock, patch
from datetime import datetime, timezone

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from discord_bot import (
    DiscordClient,
    CommandHandler,
    AlertEmbed,
    severity_color,
    CommandRateLimiter,
)


class TestUnifiedIncidentAlert(unittest.TestCase):
    """Test send_incident_alert with enriched incident data."""

    def setUp(self):
        self.client = DiscordClient(token='fake', channel_id='123')

    def _build_incident(self, **overrides):
        """Build a default incident dict with optional overrides."""
        return {
            'ip': '203.0.113.42',
            'severity': 'high',
            'narrative': 'IP 203.0.113.42 is actively attacking over 10 min [HIGH]: scanning ports on the firewall, targeting web services.',
            'signal_count': 15,
            'sources': ['firewall', 'nginx', 'ids'],
            'signal_types': ['firewall_port_scan', 'http_scan', 'ids_signature', 'path_traversal', 'syn_flood', 'brute_force', 'anomaly_temporal'],
            'phases': ['recon', 'probe', 'attack'],
            'is_escalated': False,
            'affected_targets': ['10.0.0.1:80', '10.0.0.1:443', '10.0.0.2:22'],
            'related_ips': ['203.0.113.42', '203.0.113.43'],
            'behavioral_score': 0.72,
            'dns_name': 'scanner.example.com',
            'chain_timeline': [
                {'phase': 'recon', 'signal_type': 'firewall_port_scan', 'source': 'firewall', 'timestamp': time.time() - 600},
                {'phase': 'probe', 'signal_type': 'http_scan', 'source': 'nginx', 'timestamp': time.time() - 300},
                {'phase': 'attack', 'signal_type': 'syn_flood', 'source': 'firewall', 'timestamp': time.time() - 60},
            ],
            **overrides
        }

    @patch.object(DiscordClient, '_post', return_value=True)
    def test_basic_incident_alert(self, mock_post):
        """Test basic incident alert sends correctly."""
        inc = self._build_incident()
        result = self.client.send_incident_alert(inc)
        self.assertTrue(result)
        mock_post.assert_called_once()
        payload = mock_post.call_args[0][1]
        self.assertEqual(len(payload['embeds']), 1)
        self.assertEqual(payload['username'], 'OPNsense Alert Bot')

    @patch.object(DiscordClient, '_post', return_value=True)
    def test_embed_includes_behavioral_score(self, mock_post):
        """Test behavioral score appears in embed fields."""
        inc = self._build_incident(behavioral_score=0.85)
        self.client.send_incident_alert(inc)
        embed = mock_post.call_args[0][1]['embeds'][0]
        field_names = [f['name'] for f in embed['fields']]
        # Should have a behavioral score field with emoji indicator
        score_fields = [f for f in field_names if 'Behavioral Score' in f]
        self.assertTrue(len(score_fields) > 0, "Behavioral score field missing")
        # Score indicator should be red for >0.7
        self.assertIn('🔴', score_fields[0])

    @patch.object(DiscordClient, '_post', return_value=True)
    def test_embed_includes_dns_name(self, mock_post):
        """Test DNS name appears in embed title."""
        inc = self._build_incident(dns_name='scanner.example.com')
        self.client.send_incident_alert(inc)
        embed = mock_post.call_args[0][1]['embeds'][0]
        self.assertIn('scanner.example.com', embed['title'])

    @patch.object(DiscordClient, '_post', return_value=True)
    def test_embed_includes_recommended_actions(self, mock_post):
        """Test recommended actions appear in embed for high severity."""
        inc = self._build_incident(severity='high', phases=['recon', 'attack'])
        self.client.send_incident_alert(inc)
        embed = mock_post.call_args[0][1]['embeds'][0]
        action_fields = [f for f in embed['fields'] if f['name'] == 'Recommended Actions']
        self.assertTrue(len(action_fields) > 0, "Recommended actions field missing")
        self.assertIn('Investigate', action_fields[0]['value'])

    @patch.object(DiscordClient, '_post', return_value=True)
    def test_embed_includes_attack_chain(self, mock_post):
        """Test attack chain field for multi-phase incidents."""
        inc = self._build_incident(phases=['recon', 'probe', 'attack'])
        self.client.send_incident_alert(inc)
        embed = mock_post.call_args[0][1]['embeds'][0]
        chain_fields = [f for f in embed['fields'] if f['name'] == 'Attack Chain']
        self.assertTrue(len(chain_fields) > 0, "Attack chain field missing")
        self.assertIn('recon', chain_fields[0]['value'])
        self.assertIn('probe', chain_fields[0]['value'])
        self.assertIn('attack', chain_fields[0]['value'])

    @patch.object(DiscordClient, '_post', return_value=True)
    def test_escalated_incident_title(self, mock_post):
        """Test escalated incidents get the correct title prefix."""
        inc = self._build_incident(is_escalated=True)
        self.client.send_incident_alert(inc)
        embed = mock_post.call_args[0][1]['embeds'][0]
        self.assertIn('ESCALATED', embed['title'])

    @patch.object(DiscordClient, '_post', return_value=True)
    def test_narrative_as_description(self, mock_post):
        """Test narrative is used as embed description."""
        inc = self._build_incident()
        self.client.send_incident_alert(inc)
        embed = mock_post.call_args[0][1]['embeds'][0]
        self.assertIn('actively attacking', embed['description'])

    @patch.object(DiscordClient, '_post', return_value=True)
    def test_embed_truncation_respects_field_count(self, mock_post):
        """Test description is truncated to fit Discord's 6000-char embed limit."""
        long_narrative = 'A ' * 2000  # Very long narrative
        inc = self._build_incident(narrative=long_narrative, signal_types=['sig' + str(i) for i in range(20)])
        self.client.send_incident_alert(inc)
        embed = mock_post.call_args[0][1]['embeds'][0]
        # Total embed size should be under 6500
        total = len(embed['description'])
        for f in embed['fields']:
            total += len(f['name']) + len(f['value'])
        self.assertLess(total, 6500, f"Embed total chars {total} exceeds 6000 limit")

    @patch.object(DiscordClient, '_post', return_value=True)
    def test_chain_timeline_in_embed(self, mock_post):
        """Test chain timeline field is rendered with timestamps."""
        inc = self._build_incident()
        self.client.send_incident_alert(inc)
        embed = mock_post.call_args[0][1]['embeds'][0]
        timeline_fields = [f for f in embed['fields'] if f['name'] == 'Timeline']
        self.assertTrue(len(timeline_fields) > 0, "Timeline field missing")
        # Should contain phase names
        self.assertIn('recon', timeline_fields[0]['value'])

    @patch.object(DiscordClient, '_post', return_value=True)
    def test_affected_targets_in_embed(self, mock_post):
        """Test affected targets field appears when present."""
        inc = self._build_incident()
        self.client.send_incident_alert(inc)
        embed = mock_post.call_args[0][1]['embeds'][0]
        target_fields = [f for f in embed['fields'] if f['name'] == 'Affected Targets']
        self.assertTrue(len(target_fields) > 0, "Affected targets field missing")
        self.assertIn('10.0.0.1', target_fields[0]['value'])


class TestIncidentDeduplication(unittest.TestCase):
    """Test per-IP deduplication within DEDUP_SECONDS."""

    def setUp(self):
        self.client = DiscordClient(token='fake', channel_id='123')

    @patch.object(DiscordClient, '_post', return_value=True)
    def test_first_alert_sends(self, mock_post):
        """First alert for an IP should be sent."""
        inc = {'ip': '1.2.3.4', 'severity': 'low', 'narrative': '', 'signal_count': 1, 'sources': [], 'signal_types': [], 'phases': [], 'is_escalated': False}
        result = self.client.send_incident_alert(inc)
        self.assertTrue(result)

    @patch.object(DiscordClient, '_post', return_value=True)
    def test_duplicate_within_window_suppressed(self, mock_post):
        """Second alert for the same IP within DEDUP_SECONDS should be suppressed."""
        inc = {'ip': '1.2.3.4', 'severity': 'low', 'narrative': '', 'signal_count': 1, 'sources': [], 'signal_types': [], 'phases': [], 'is_escalated': False}
        self.client.send_incident_alert(inc)
        mock_post.reset_mock()
        result = self.client.send_incident_alert(inc)
        self.assertFalse(result)
        mock_post.assert_not_called()

    @patch.object(DiscordClient, '_post', return_value=True)
    def test_different_ip_not_suppressed(self, mock_post):
        """Alert for a different IP should not be suppressed."""
        inc1 = {'ip': '1.2.3.4', 'severity': 'low', 'narrative': '', 'signal_count': 1, 'sources': [], 'signal_types': [], 'phases': [], 'is_escalated': False}
        inc2 = {'ip': '5.6.7.8', 'severity': 'low', 'narrative': '', 'signal_count': 1, 'sources': [], 'signal_types': [], 'phases': [], 'is_escalated': False}
        self.client.send_incident_alert(inc1)
        mock_post.reset_mock()
        result = self.client.send_incident_alert(inc2)
        self.assertTrue(result)
        mock_post.assert_called_once()


class TestRecommendActions(unittest.TestCase):
    """Test _recommend_actions method."""

    def setUp(self):
        self.client = DiscordClient(token='fake', channel_id='123')

    def test_critical_severity_immediate_block(self):
        """Critical severity should recommend immediate firewall block."""
        actions = self.client._recommend_actions('critical', ['exploit'], [], True)
        self.assertTrue(any('Block source IP' in a for a in actions))

    def test_high_severity_investigate(self):
        """High severity should recommend investigation."""
        actions = self.client._recommend_actions('high', ['attack'], [], False)
        self.assertTrue(any('Investigate' in a for a in actions))

    def test_exploit_phase_recommendation(self):
        """Exploit phase should recommend checking for lateral movement."""
        actions = self.client._recommend_actions('high', ['exploit'], [], False)
        self.assertTrue(any('lateral movement' in a for a in actions))

    def test_attack_phase_recommendation(self):
        """Attack phase should recommend WAF/IPS check."""
        actions = self.client._recommend_actions('medium', ['attack'], [], False)
        self.assertTrue(any('WAF' in a or 'IPS' in a for a in actions))

    def test_recon_only_recommendation(self):
        """Recon-only should suggest IP reputation lookup."""
        actions = self.client._recommend_actions('low', ['recon'], [], False)
        self.assertTrue(any('reputation' in a.lower() for a in actions))

    def test_low_severity_no_actions(self):
        """Low severity without attack phases should have no severity-based actions."""
        actions = self.client._recommend_actions('low', [], [], False)
        severity_actions = [a for a in actions if a.startswith(('🔴', '🟠', '🟡'))]
        self.assertEqual(len(severity_actions), 0)


class TestScoreToThreat(unittest.TestCase):
    """Test _score_to_threat mapping."""

    def setUp(self):
        self.client = DiscordClient(token='fake', channel_id='123')

    def test_critical_range(self):
        self.assertEqual(self.client._score_to_threat(0.9), 'CRITICAL')

    def test_high_range(self):
        self.assertEqual(self.client._score_to_threat(0.7), 'HIGH')

    def test_medium_range(self):
        self.assertEqual(self.client._score_to_threat(0.5), 'MEDIUM')

    def test_low_range(self):
        self.assertEqual(self.client._score_to_threat(0.3), 'LOW')

    def test_minimal_range(self):
        self.assertEqual(self.client._score_to_threat(0.1), 'MINIMAL')


class TestIpLookupInIncidentCommand(unittest.TestCase):
    """Test /incident IP-based lookup in CommandHandler."""

    def setUp(self):
        self.handler = CommandHandler()

    def test_looks_like_ipv4(self):
        self.assertTrue(self.handler._looks_like_ip('192.168.1.1'))
        self.assertTrue(self.handler._looks_like_ip('10.0.0.1'))
        self.assertFalse(self.handler._looks_like_ip('inc_abc123'))
        self.assertFalse(self.handler._looks_like_ip('hello'))
        self.assertFalse(self.handler._looks_like_ip('999.999.999.999'))

    def test_looks_like_ipv6(self):
        self.assertTrue(self.handler._looks_like_ip('2001:db8::1'))

    @patch.object(CommandHandler, '_find_inc_id_by_ip', return_value='inc_test123')
    def test_ip_lookup_with_correlation_engine(self, mock_find):
        """Test IP lookup goes through correlation engine."""
        corr = MagicMock()
        corr.get_incident_by_ip.return_value = MagicMock()
        corr.get_incident_by_ip.return_value.get_attack_chain.return_value = []
        corr.get_incident_by_ip.return_value.get_narrative.return_value = ''
        mgr = MagicMock()
        mgr._ip_incidents = {'1.2.3.4': ['inc_test123']}
        mgr._incidents = {'inc_test123': MagicMock(is_active=True)}
        mgr.get_incident.return_value = {
            'ip': '1.2.3.4',
            'status': 'new',
            'severity': 'high',
            'signal_count': 5,
            'feedback_score': 0.5,
            'feedback_count': 2,
            'signal_types': ['port_scan'],
            'description': 'Test incident',
            'group_id': None,
        }

        self.handler.agent = MagicMock()
        self.handler.agent.incident_manager = mgr
        self.handler.agent.correlation_engine = corr
        self.handler.agent.behavior_profiler = None  # No behavioral engine in test
        self.handler.agent.reverse_dns = None  # No DNS in test

        result = self.handler._cmd_incident('1.2.3.4')
        # Should not be an error result
        self.assertFalse('not found' in result.content.lower() or 'No active' in result.content)

    def test_ip_lookup_no_active_incident(self):
        """Test IP lookup when no active incident exists."""
        corr = MagicMock()
        corr.get_incident_by_ip.return_value = None
        mgr = MagicMock()

        self.handler.agent = MagicMock()
        self.handler.agent.incident_manager = mgr
        self.handler.agent.correlation_engine = corr

        result = self.handler._cmd_incident('1.2.3.4')
        self.assertIn('No active incident', result.content)


if __name__ == '__main__':
    unittest.main()
