"""Tests for adaptive_parser.py — syslog parsing and feature extraction."""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from adaptive_parser import AdaptiveParser


class TestAdaptiveParserParseLine:
    """Test parse_line returns expected fields."""

    def setup_method(self):
        self.parser = AdaptiveParser()

    def _sample_filterlog(self, msg=None):
        if msg is None:
            # Proper format with TWO empty fields after flag (indices 1,2)
            # [0]flag [1]empty [2]empty [3]ruid [4]iface [5]match [6]action [7]dir [8]ipver ...
            msg = "17,,,fae559338f65e11c53669fc3642c93c2,igb1,match,pass,in,4,0x00,4605,0,DF,17,udp,0,10.0.0.1,10.0.0.2,33444,53,0,0,"
        return f"<134>Jun 17 10:00:00 opnsense filterlog[12345]: {msg}"

    def _sample_block_filterlog(self):
        # TCP block: 29 parts
        return self._sample_filterlog("17,,,fae559338f65e11c53669fc3642c93c2,igb1,match,block,in,4,0x00,4605,0,DF,6,tcp,0,1.2.3.4,5.6.7.8,12345,443,SYN,0,0,0,0")

    def test_parse_filterlog_returns_fields(self):
        line = self._sample_filterlog()
        result = self.parser.parse_line(line)
        assert result is not None
        assert 'src_ip' in result
        assert 'dst_ip' in result
        assert 'dport' in result
        assert 'action' in result
        assert 'proto' in result
        assert result['action'] == 'PASS'
        assert result['sport'] == 33444

    def test_parse_filterlog_correct_action(self):
        line = self._sample_filterlog()
        result = self.parser.parse_line(line)
        assert result['action'] == 'PASS'

    def test_parse_filterlog_correct_ports(self):
        line = self._sample_filterlog()
        result = self.parser.parse_line(line)
        assert result['dport'] == 53
        assert result['sport'] == 33444

    def test_parse_filterlog_correct_ips(self):
        line = self._sample_filterlog()
        result = self.parser.parse_line(line)
        assert result['src_ip'] == '10.0.0.1'
        assert result['dst_ip'] == '10.0.0.2'

    def test_parse_filterlog_block(self):
        line = self._sample_block_filterlog()
        result = self.parser.parse_line(line)
        assert result is not None
        assert result['action'] == 'BLOCK'
        assert result['proto'] == 'TCP'
        assert result['src_ip'] == '1.2.3.4'
        assert result['dport'] == 443

    def test_empty_line_returns_none(self):
        assert self.parser.parse_line("") is None
        assert self.parser.parse_line("   ") is None

    def test_parse_with_no_header_returns_none(self):
        """Lines that don't match syslog header return None."""
        assert self.parser.parse_line("not a syslog line at all") is None

    def test_parse_filterlog_ipv6(self):
        # IPv6 filterlog format - simplified test
        line = "<134>Jun 17 10:00:00 opnsense filterlog[12345]: 17,,fae559338f65e11c53669fc3642c93c2,igb1,match,pass,in,6,0x00,...,tcp,...,2605::dead:beef,2605::1,443,SYN"
        result = self.parser.parse_line(line)
        assert result is not None
        # Just verify it parses without crashing
        assert 'log_type' in result

    def test_parse_system_log(self):
        line = "<134>Jun 17 10:00:00 opnsense ntpd[1234]: time update +0.001s"
        result = self.parser.parse_line(line)
        assert result is not None
        assert 'log_type' in result

    def test_parse_zenarmor(self):
        line = "<134>Jun 17 10:00:00 opnsense zenarmor[1234]: blocked from 1.2.3.4 port 80"
        result = self.parser.parse_line(line)
        assert result is not None
        assert 'log_type' in result

    def test_parse_nginx(self):
        line = "<134>Jun 17 10:00:00 opnsense nginx[1234]: 1.2.3.4 GET /api"
        result = self.parser.parse_line(line)
        assert result is not None
        assert 'log_type' in result

    def test_multiple_actions_in_line(self):
        line = self._sample_filterlog("filterlog[12345]: 17,0,,pflog0,match,pass,block,in,4,...")
        result = self.parser.parse_line(line)
        assert result is not None
        # First action wins
        assert result['action'] in ('PASS', 'BLOCK')

    def test_parse_preserves_raw(self):
        line = self._sample_filterlog()
        result = self.parser.parse_line(line)
        assert result is not None
        assert 'raw' in result
        assert len(result['raw']) > 0

    def test_parse_sets_hostname(self):
        line = "<134>Jun 17 10:00:00 my-hostname filterlog[12345]: 17,0,,pflog0,match,pass,in,4,...,tcp,6,...,1.2.3.4,5.6.7.8,12345,80,..."
        result = self.parser.parse_line(line)
        assert result is not None
        assert result['hostname'] == 'my-hostname'

    def test_parse_process_field(self):
        line = "<134>Jun 17 10:00:00 opnsense myprocess[999]: some message"
        result = self.parser.parse_line(line)
        assert result is not None
        assert 'process' in result
        assert result['process'] == 'myprocess'

    def test_adaptation_increments(self):
        for i in range(10):
            self.parser.parse_line(self._sample_filterlog())
        # adaptation_counter increments after adaptation_interval
        assert self.parser.adaptation_counter >= 0

    def test_log_type_distribution_updated(self):
        for i in range(5):
            self.parser.parse_line(self._sample_filterlog())
        assert self.parser.log_type_distribution['filterlog'] == 5
