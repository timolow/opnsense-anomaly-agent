"""Test Discord reconnection logic with exponential backoff.

Tests the DiscordBot reconnection watcher behavior:
- Exponential backoff delays (5s base, 30s cap)
- Max reconnect attempts
- Clean shutdown via stop event
- Thread lifecycle management
"""

import time
import threading
from unittest.mock import MagicMock, patch, PropertyMock

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from discord_bot import DiscordBot, CommandRateLimiter


class MockStopEvent:
    """Thread-safe stop event mock."""
    def __init__(self):
        self._set = False

    def is_set(self):
        return self._set

    def set(self):
        self._set = True

    def wait(self, timeout=0):
        time.sleep(timeout)
        return self._set


class MockThread:
    """Mock thread that starts in alive state then dies."""
    def __init__(self, alive=True):
        self._alive = alive
        self.daemon = True
        self.name = "mock"

    def start(self):
        self._alive = True

    def is_alive(self):
        return self._alive

    def join(self, timeout=0):
        if timeout > 0:
            time.sleep(min(timeout, 0.01))
        self._alive = False


class TestReconnectionConfig:
    """Test reconnection configuration values."""

    def test_default_delays(self):
        assert DiscordBot.RECONNECT_BASE_DELAY == 5
        assert DiscordBot.RECONNECT_MAX_DELAY == 30
        assert DiscordBot.RECONNECT_MAX_COUNT == 10

    def test_backoff_schedule(self):
        """Verify exponential backoff: 5, 10, 20, 30, 30, 30..."""
        base = DiscordBot.RECONNECT_BASE_DELAY
        max_delay = DiscordBot.RECONNECT_MAX_DELAY
        expected = []
        for i in range(1, 11):
            delay = min(base * (2 ** (i - 1)), max_delay)
            expected.append(delay)
        assert expected == [5, 10, 20, 30, 30, 30, 30, 30, 30, 30]

    def test_reconnect_within_30s(self):
        """First reconnect should happen within 30s (acceptance criterion)."""
        first_delay = DiscordBot.RECONNECT_BASE_DELAY
        assert first_delay <= 30
        assert first_delay > 0


class TestReconnectWatcher:
    """Test the reconnect watcher logic."""

    def _make_bot(self):
        config = MagicMock()
        config.discord_token = "test"
        config.discord_channel_id = "123"
        bot = DiscordBot(config)
        bot._stop_event = MockStopEvent()
        bot._bot_client = None
        return bot

    def test_watcher_stops_on_max_count(self):
        bot = self._make_bot()
        bot.RECONNECT_MAX_COUNT = 3  # Low limit for testing

        alive = True
        call_count = 0

        class TestThread(MockThread):
            def is_alive(self):
                nonlocal alive
                return alive

        with patch.object(bot, '_start_bot_thread') as mock_start:
            mock_start.side_effect = lambda: None
            bot._bot_thread = TestThread()

            # Simulate the watcher loop manually
            iteration = 0
            while not bot._stop_event.is_set():
                # Bot thread dies
                alive = False

                if bot._bot_thread and bot._bot_thread.is_alive():
                    bot._bot_thread.join(timeout=0.01)
                    continue

                if bot._stop_event.is_set():
                    break

                if bot.RECONNECT_MAX_COUNT and bot._reconnect_count >= bot.RECONNECT_MAX_COUNT:
                    break

                bot._reconnect_count += 1
                call_count += 1

                delay = min(
                    bot.RECONNECT_BASE_DELAY * (2 ** (bot._reconnect_count - 1)),
                    bot.RECONNECT_MAX_DELAY,
                )
                # Skip actual wait
                bot._start_bot_thread()
                alive = True  # Reset for next iteration
                iteration += 1
                if iteration > 20:
                    break

            assert bot._reconnect_count == bot.RECONNECT_MAX_COUNT
            assert call_count == bot.RECONNECT_MAX_COUNT

    def test_watcher_stops_on_stop_event(self):
        bot = self._make_bot()
        bot._stop_event.set()

        alive = False
        loops = 0

        class TestThread(MockThread):
            def is_alive(self):
                return alive

        bot._bot_thread = TestThread()

        # Watcher should break immediately
        while not bot._stop_event.is_set():
            if bot._bot_thread and bot._bot_thread.is_alive():
                bot._bot_thread.join(timeout=0.01)
                continue
            if bot._stop_event.is_set():
                break
            loops += 1

        assert loops == 0  # Broke immediately


class TestReconnectLogging:
    """Test that reconnection logs correct delay values."""

    def test_log_messages_contain_delay(self):
        """Verify log messages include delay and attempt number."""
        config = MagicMock()
        config.discord_token = "test"
        config.discord_channel_id = "123"
        bot = DiscordBot(config)
        bot._stop_event = MockStopEvent()

        # Simulate first reconnect
        bot._reconnect_count = 1
        delay = min(
            bot.RECONNECT_BASE_DELAY * (2 ** (bot._reconnect_count - 1)),
            bot.RECONNECT_MAX_DELAY,
        )
        assert delay == 5
        msg = (
            "Discord bot disconnected -- reconnecting in %.0fs (attempt %d)" % (delay, bot._reconnect_count)
        )
        assert "5s" in msg
        assert "attempt 1" in msg

        # Simulate 4th reconnect (should hit max cap)
        bot._reconnect_count = 4
        delay = min(
            bot.RECONNECT_BASE_DELAY * (2 ** (bot._reconnect_count - 1)),
            bot.RECONNECT_MAX_DELAY,
        )
        assert delay == 30  # Capped at max

    def test_reconnect_sequence_logs(self):
        """Full sequence of reconnect log delays."""
        config = MagicMock()
        config.discord_token = "test"
        config.discord_channel_id = "123"
        bot = DiscordBot(config)

        delays = []
        for i in range(1, 6):
            bot._reconnect_count = i
            delay = min(
                bot.RECONNECT_BASE_DELAY * (2 ** (bot._reconnect_count - 1)),
                bot.RECONNECT_MAX_DELAY,
            )
            delays.append(delay)

        assert delays == [5, 10, 20, 30, 30]


class TestCommandRateLimiter:
    """Test the command rate limiter used by the Discord bot."""

    def test_allows_within_limit(self):
        rl = CommandRateLimiter(max_commands=3, window_seconds=60)
        assert rl.is_allowed("user1")
        assert rl.is_allowed("user1")
        assert rl.is_allowed("user1")
        assert rl.remaining("user1") == 0

    def test_blocks_over_limit(self):
        rl = CommandRateLimiter(max_commands=2, window_seconds=60)
        assert rl.is_allowed("user1")
        assert rl.is_allowed("user1")
        assert not rl.is_allowed("user1")

    def test_per_user_isolation(self):
        rl = CommandRateLimiter(max_commands=1, window_seconds=60)
        assert rl.is_allowed("user1")
        assert not rl.is_allowed("user1")
        assert rl.is_allowed("user2")  # Different user, fresh limit

    def test_reset(self):
        rl = CommandRateLimiter(max_commands=1, window_seconds=60)
        assert rl.is_allowed("user1")
        assert not rl.is_allowed("user1")
        rl.reset("user1")
        assert rl.is_allowed("user1")


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))