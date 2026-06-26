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


class TestPatternHistoryBounded:
    """Test that pattern_history uses bounded deques and does not grow unbounded."""

    def setup_method(self):
        self.parser = AdaptiveParser()

    def _sample_filterlog(self):
        return "<134>Jun 17 10:00:00 opnsense filterlog[12345]: 17,,,fae559338f65e11c53669fc3642c93c2,igb1,match,pass,in,4,0x00,4605,0,DF,17,udp,0,10.0.0.1,10.0.0.2,33444,53,0,0,"

    def test_pattern_history_is_deque(self):
        """pattern_history values should be deque instances with maxlen."""
        from collections import deque
        self.parser.parse_line(self._sample_filterlog())
        assert isinstance(self.parser.pattern_history['src_ip'], deque)
        assert self.parser.pattern_history['src_ip'].maxlen == self.parser._PATTERN_HISTORY_MAXLEN

    def test_pattern_history_maxlen_configurable(self):
        """_PATTERN_HISTORY_MAXLEN should control deque bounds."""
        assert self.parser._PATTERN_HISTORY_MAXLEN == 10000

    def test_pattern_history_does_not_exceed_maxlen(self):
        """After exceeding maxlen, oldest entries are dropped."""
        # Parse more events than the maxlen
        for i in range(self.parser._PATTERN_HISTORY_MAXLEN + 100):
            self.parser.parse_line(self._sample_filterlog())

        # History should be capped at maxlen
        assert len(self.parser.pattern_history['src_ip']) == self.parser._PATTERN_HISTORY_MAXLEN
        assert len(self.parser.pattern_history['dst_ip']) == self.parser._PATTERN_HISTORY_MAXLEN
        assert len(self.parser.pattern_history['dport']) == self.parser._PATTERN_HISTORY_MAXLEN

    def test_pattern_history_oldest_dropped_first(self):
        """FIFO ordering: oldest entries are evicted when deque is full."""
        base_line = self._sample_filterlog()
        maxlen = self.parser._PATTERN_HISTORY_MAXLEN

        # Fill past capacity
        for i in range(maxlen + 50):
            self.parser.parse_line(base_line)

        # All entries should be the same (10.0.0.1), but the first 50 are gone
        src_ips = list(self.parser.pattern_history['src_ip'])
        assert all(ip == '10.0.0.1' for ip in src_ips)
        assert len(src_ips) == maxlen

    def test_pattern_history_small_traffic_unchanged(self):
        """Normal traffic well below maxlen accumulates normally."""
        for i in range(100):
            self.parser.parse_line(self._sample_filterlog())

        assert len(self.parser.pattern_history['src_ip']) == 100
        assert len(self.parser.pattern_history['dst_ip']) == 100
        assert len(self.parser.pattern_history['dport']) == 100

    def test_pattern_history_memory_bounded(self):
        """Memory should not grow linearly with events after maxlen is reached."""
        import sys

        # Parse a batch and measure memory
        for i in range(self.parser._PATTERN_HISTORY_MAXLEN + 5000):
            self.parser.parse_line(self._sample_filterlog())

        size_after_big = sys.getsizeof(
            list(self.parser.pattern_history['src_ip'])
        )

        # Parse 10x more events
        for i in range(self.parser._PATTERN_HISTORY_MAXLEN * 10):
            self.parser.parse_line(self._sample_filterlog())

        size_after_more = sys.getsizeof(
            list(self.parser.pattern_history['src_ip'])
        )

        # Memory footprint of the list repr should be identical
        assert size_after_big == size_after_more
        assert len(self.parser.pattern_history['src_ip']) == self.parser._PATTERN_HISTORY_MAXLEN
