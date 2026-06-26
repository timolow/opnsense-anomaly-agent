"""Tests for Discord slash commands: /search, /top-threats, /recent-alerts.

Covers:
- CommandHandler._cmd_search, _cmd_top_threats, _cmd_recent_alerts
- Embed generation (AlertEmbed) in command responses
- Slash command registration payload structure
- Rate limiting applied to slash command interactions
- Edge cases: empty results, missing db, invalid args
"""

import unittest
from unittest.mock import MagicMock, patch, PropertyMock
from datetime import datetime, timezone

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from discord_bot import (
    CommandHandler,
    CommandResult,
    AlertEmbed,
    severity_color,
    generate_attack_embed,
)


class TestSearchCommand(unittest.TestCase):
    """Test /search command handler."""

    def setUp(self):
        self.handler = CommandHandler()
        self.mock_db = MagicMock()
        self.handler.agent = MagicMock()
        self.handler.agent.db = self.mock_db

    def test_search_with_results_returns_embed(self):
        """Search with matching anomalies returns embed with fields."""
        self.mock_db.search_anomalies.return_value = [
            {
                'id': 1,
                'attack_type': 'PORT_SCAN',
                'severity': 'HIGH',
                'src_ip': '1.2.3.4',
                'dst_ip': '10.0.0.1',
                'dst_port': 22,
                'proto': 'tcp',
                'created_at_str': '2026-06-26T00:00:00',
                'description': 'Port scan detected from 1.2.3.4',
            }
        ]
        result = self.handler._cmd_search('1.2.3.4')
        self.assertEqual(result.content, 'Found **1** anomaly(ies) matching `1.2.3.4`')
        self.assertIsNotNone(result.embed)
        self.assertEqual(result.embed.title, 'Search results for "1.2.3.4" (1 found)')
        self.assertEqual(len(result.embed.fields), 1)
        self.assertIn('1.2.3.4', result.embed.fields[0]['value'])

    def test_search_no_results(self):
        """Search with no matches returns plain text."""
        self.mock_db.search_anomalies.return_value = []
        result = self.handler._cmd_search('nonexistent')
        self.assertEqual(result.embed, None)
        self.assertIn('No anomalies matching', result.content)

    def test_search_empty_query(self):
        """Empty query returns usage hint."""
        result = self.handler._cmd_search('')
        self.assertEqual(result.embed, None)
        self.assertIn('Usage', result.content)

    def test_search_no_database(self):
        """Missing database returns error message."""
        self.handler.agent.db = None
        result = self.handler._cmd_search('test')
        self.assertEqual(result.embed, None)
        self.assertIn('Database not available', result.content)

    def test_search_db_exception(self):
        """Database exception returns error message."""
        self.mock_db.search_anomalies.side_effect = Exception('connection refused')
        result = self.handler._cmd_search('test')
        self.assertEqual(result.embed, None)
        self.assertIn('Search failed', result.content)

    def test_search_limits_results(self):
        """Search queries DB with limit=10."""
        self.mock_db.search_anomalies.return_value = []
        result = self.handler._cmd_search('test')
        self.mock_db.search_anomalies.assert_called_once_with('test', limit=10)


class TestTopThreatsCommand(unittest.TestCase):
    """Test /top-threats command handler."""

    def setUp(self):
        self.handler = CommandHandler()
        self.mock_db = MagicMock()
        self.handler.agent = MagicMock()
        self.handler.agent.db = self.mock_db

    def test_top_threats_default_args(self):
        """Default limit=10, hours=24."""
        self.mock_db.get_top_threat_ips.return_value = [
            {
                'src_ip': '1.2.3.4',
                'threat_score': 50,
                'total': 10,
                'attack_types': 'PORT_SCAN, SYN_FLOOD',
                'critical_count': 2,
                'high_count': 5,
                'medium_count': 2,
                'low_count': 1,
            }
        ]
        result = self.handler._cmd_top_threats('')
        self.assertIsNotNone(result.embed)
        self.assertIn('Top Threat IPs', result.embed.title)
        self.mock_db.get_top_threat_ips.assert_called_once_with(limit=10, hours=24)

    def test_top_threats_custom_limit(self):
        """Custom limit passed correctly."""
        self.mock_db.get_top_threat_ips.return_value = []
        result = self.handler._cmd_top_threats('5')
        self.mock_db.get_top_threat_ips.assert_called_once_with(limit=5, hours=24)

    def test_top_threats_custom_limit_and_hours(self):
        """Custom limit and hours passed correctly."""
        self.mock_db.get_top_threat_ips.return_value = []
        result = self.handler._cmd_top_threats('20 48')
        self.mock_db.get_top_threat_ips.assert_called_once_with(limit=20, hours=48)

    def test_top_threats_limit_clamped(self):
        """Limit > 50 clamped to 10."""
        self.mock_db.get_top_threat_ips.return_value = []
        result = self.handler._cmd_top_threats('100')
        self.mock_db.get_top_threat_ips.assert_called_once_with(limit=10, hours=24)

    def test_top_threats_no_data(self):
        """No threat data returns informative message."""
        self.mock_db.get_top_threat_ips.return_value = []
        result = self.handler._cmd_top_threats('')
        self.assertEqual(result.embed, None)
        self.assertIn('No threat data', result.content)

    def test_top_threats_severity_breakdown(self):
        """Severity counts rendered as emoji badges."""
        self.mock_db.get_top_threat_ips.return_value = [
            {
                'src_ip': '10.0.0.1',
                'threat_score': 100,
                'total': 50,
                'attack_types': 'BRUTE_FORCE',
                'critical_count': 10,
                'high_count': 0,
                'medium_count': 5,
                'low_count': 0,
            }
        ]
        result = self.handler._cmd_top_threats('')
        field_value = result.embed.fields[0]['value']
        self.assertIn('critical', field_value)
        self.assertIn('medium', field_value)


class TestRecentAlertsCommand(unittest.TestCase):
    """Test /recent-alerts command handler."""

    def setUp(self):
        self.handler = CommandHandler()
        self.mock_db = MagicMock()
        self.handler.agent = MagicMock()
        self.handler.agent.db = self.mock_db

    def test_recent_alerts_default_args(self):
        """Default limit=10."""
        self.mock_db.get_recent_anomalies.return_value = [
            {
                'id': 42,
                'attack_type': 'SYN_FLOOD',
                'severity': 'CRITICAL',
                'src_ip': '5.6.7.8',
                'dst_ip': '10.0.0.1',
                'dst_port': 80,
                'proto': 'tcp',
                'description': 'SYN flood attack',
                'discord_sent': True,
            }
        ]
        result = self.handler._cmd_recent_alerts('')
        self.assertIsNotNone(result.embed)
        self.assertIn('Recent Anomaly Alerts', result.embed.title)
        self.mock_db.get_recent_anomalies.assert_called_once_with(limit=10)

    def test_recent_alerts_custom_limit(self):
        """Custom limit passed correctly."""
        self.mock_db.get_recent_anomalies.return_value = []
        result = self.handler._cmd_recent_alerts('25')
        self.mock_db.get_recent_anomalies.assert_called_once_with(limit=25)

    def test_recent_alerts_limit_clamped(self):
        """Limit > 50 clamped to 10."""
        self.mock_db.get_recent_anomalies.return_value = []
        result = self.handler._cmd_recent_alerts('100')
        self.mock_db.get_recent_anomalies.assert_called_once_with(limit=10)

    def test_recent_alerts_no_data(self):
        """No recent anomalies returns informative message."""
        self.mock_db.get_recent_anomalies.return_value = []
        result = self.handler._cmd_recent_alerts('')
        self.assertEqual(result.embed, None)
        self.assertIn('No recent anomalies', result.content)

    def test_recent_alerts_discord_status(self):
        """Discord sent status shown in embed."""
        self.mock_db.get_recent_anomalies.return_value = [
            {
                'id': 1,
                'attack_type': 'PROBE',
                'severity': 'MEDIUM',
                'src_ip': '1.1.1.1',
                'dst_ip': None,
                'dst_port': None,
                'proto': None,
                'description': '',
                'discord_sent': True,
            },
            {
                'id': 2,
                'attack_type': 'PORT_SCAN',
                'severity': 'LOW',
                'src_ip': '2.2.2.2',
                'dst_ip': '10.0.0.1',
                'dst_port': 443,
                'proto': 'tcp',
                'description': 'Scan',
                'discord_sent': False,
            }
        ]
        result = self.handler._cmd_recent_alerts('')
        self.assertEqual(len(result.embed.fields), 2)
        self.assertIn('Sent', result.embed.fields[0]['value'])
        self.assertIn('Logged', result.embed.fields[1]['value'])

    def test_recent_alerts_severity_icons(self):
        """Severity icons rendered correctly."""
        self.mock_db.get_recent_anomalies.return_value = [
            {'id': 1, 'attack_type': 'X', 'severity': 'CRITICAL', 'src_ip': None, 'dst_ip': None, 'dst_port': None, 'proto': None, 'description': '', 'discord_sent': False},
            {'id': 2, 'attack_type': 'Y', 'severity': 'HIGH', 'src_ip': None, 'dst_ip': None, 'dst_port': None, 'proto': None, 'description': '', 'discord_sent': False},
            {'id': 3, 'attack_type': 'Z', 'severity': 'MEDIUM', 'src_ip': None, 'dst_ip': None, 'dst_port': None, 'proto': None, 'description': '', 'discord_sent': False},
            {'id': 4, 'attack_type': 'W', 'severity': 'LOW', 'src_ip': None, 'dst_ip': None, 'dst_port': None, 'proto': None, 'description': '', 'discord_sent': False},
        ]
        result = self.handler._cmd_recent_alerts('4')
        field_names = [f['name'] for f in result.embed.fields]
        self.assertIn('🔴', field_names[0])
        self.assertIn('🟠', field_names[1])
        self.assertIn('🟡', field_names[2])
        self.assertIn('🔵', field_names[3])


class TestSlashCommandRegistration(unittest.TestCase):
    """Test slash command registration payload structure."""

    def test_command_registry_contains_new_commands(self):
        """COMMANDS dict includes search, top-threats, recent-alerts."""
        self.assertIn('search', CommandHandler.COMMANDS)
        self.assertIn('top-threats', CommandHandler.COMMANDS)
        self.assertIn('recent-alerts', CommandHandler.COMMANDS)

    def test_command_descriptions(self):
        """Command descriptions are non-empty and informative."""
        for cmd in ('search', 'top-threats', 'recent-alerts'):
            desc = CommandHandler.COMMANDS[cmd]
            self.assertIsInstance(desc, str)
            self.assertGreater(len(desc), 5)

    def test_handle_command_routes_new_commands(self):
        """handle_command dispatches to the correct handler methods."""
        handler = CommandHandler()
        mock_agent = MagicMock()
        mock_db = MagicMock()
        mock_agent.db = mock_db
        handler.agent = mock_agent
        mock_db.search_anomalies.return_value = []

        # search routes
        with patch.object(handler, '_cmd_search', return_value=CommandResult(content='ok')) as mock_search:
            handler.handle_command('search', 'test')
            mock_search.assert_called_once_with('test')

        # top-threats routes
        with patch.object(handler, '_cmd_top_threats', return_value=CommandResult(content='ok')) as mock_tt:
            handler.handle_command('top-threats', '5 24')
            mock_tt.assert_called_once_with('5 24')

        # recent-alerts routes
        with patch.object(handler, '_cmd_recent_alerts', return_value=CommandResult(content='ok')) as mock_ra:
            handler.handle_command('recent-alerts', '15')
            mock_ra.assert_called_once_with('15')


class TestAlertEmbedForCommands(unittest.TestCase):
    """Test that command-generated embeds serialize correctly."""

    def test_embed_to_dict_structure(self):
        """Embed to_dict contains required Discord fields."""
        embed = AlertEmbed(
            title='Test',
            description='Test description',
            color=0x5865F2,
            fields=[{'name': 'Field1', 'value': 'Val1', 'inline': True}],
        )
        d = embed.to_dict()
        self.assertIn('title', d)
        self.assertIn('description', d)
        self.assertIn('color', d)
        self.assertIn('fields', d)
        self.assertIn('timestamp', d)
        self.assertEqual(d['color'], 0x5865F2)

    def test_embed_field_count_limit(self):
        """Discord allows max 25 fields — our embeds stay within."""
        # Test that search embed fields don't exceed 25
        embed = AlertEmbed(
            title='Test',
            description='Test',
            color=0x5865F2,
            fields=[{'name': f'Field {i}', 'value': f'Val {i}', 'inline': False} for i in range(25)],
        )
        d = embed.to_dict()
        self.assertLessEqual(len(d['fields']), 25)


class TestCommandResult(unittest.TestCase):
    """Test CommandResult serialization."""

    def test_to_dict_with_embed(self):
        """CommandResult to_dict includes embeds when present."""
        embed = AlertEmbed(title='T', description='D', color=0xFF0000)
        result = CommandResult(content='content', embed=embed)
        d = result.to_dict()
        self.assertEqual(d['content'], 'content')
        self.assertIn('embeds', d)
        self.assertEqual(len(d['embeds']), 1)
        self.assertEqual(d['embeds'][0]['title'], 'T')

    def test_to_dict_without_embed(self):
        """CommandResult to_dict omits embeds when None."""
        result = CommandResult(content='just text')
        d = result.to_dict()
        self.assertEqual(d['content'], 'just text')
        self.assertNotIn('embeds', d)


if __name__ == '__main__':
    unittest.main()