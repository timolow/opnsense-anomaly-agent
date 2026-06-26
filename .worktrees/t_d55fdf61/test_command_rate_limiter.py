"""Tests for CommandRateLimiter — per-user rate limiting on Discord chat commands."""

import os
import sys
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from discord_bot import CommandRateLimiter


class TestCommandRateLimiterDefaults(unittest.TestCase):
    """Verify default config: 5 commands per 60 seconds."""

    def setUp(self):
        self.limiter = CommandRateLimiter()

    def test_default_max_commands(self):
        self.assertEqual(self.limiter.max_commands, 5)

    def test_default_window_seconds(self):
        self.assertEqual(self.limiter.window_seconds, 60)

    def test_allows_first_command(self):
        self.assertTrue(self.limiter.is_allowed("user_1"))

    def test_allows_up_to_max_commands(self):
        for _ in range(5):
            self.assertTrue(self.limiter.is_allowed("user_1"))

    def test_blocks_after_max_commands(self):
        for _ in range(5):
            self.limiter.is_allowed("user_1")
        self.assertFalse(self.limiter.is_allowed("user_1"))


class TestCommandRateLimiterPerUser(unittest.TestCase):
    """Rate limits are independent per user."""

    def setUp(self):
        self.limiter = CommandRateLimiter()

    def test_independent_users(self):
        # User A hits limit
        for _ in range(5):
            self.limiter.is_allowed("user_a")
        self.assertFalse(self.limiter.is_allowed("user_a"))

        # User B still allowed
        self.assertTrue(self.limiter.is_allowed("user_b"))

    def test_remaining_per_user(self):
        for _ in range(3):
            self.limiter.is_allowed("user_a")
        self.assertEqual(self.limiter.remaining("user_a"), 2)
        self.assertEqual(self.limiter.remaining("user_b"), 5)


class TestCommandRateLimiterSlidingWindow(unittest.TestCase):
    """Window slides — old entries expire."""

    def test_window_expiry(self):
        limiter = CommandRateLimiter(max_commands=3, window_seconds=1)

        # Fill up
        for _ in range(3):
            limiter.is_allowed("user")
        self.assertFalse(limiter.is_allowed("user"))

        # Wait for window to expire
        time.sleep(1.1)

        # Should be allowed again
        self.assertTrue(limiter.is_allowed("user"))

    def test_partial_expiry(self):
        limiter = CommandRateLimiter(max_commands=3, window_seconds=1)

        limiter.is_allowed("user")
        time.sleep(0.5)
        limiter.is_allowed("user")
        time.sleep(0.5)
        # First entry expired, second is still valid
        limiter.is_allowed("user")
        # Now at 2 (second entry + this one); should still allow one more
        self.assertEqual(limiter.remaining("user"), 1)


class TestCommandRateLimiterRemaining(unittest.TestCase):
    """remaining() returns correct count."""

    def setUp(self):
        self.limiter = CommandRateLimiter(max_commands=5, window_seconds=60)

    def test_initial_remaining(self):
        self.assertEqual(self.limiter.remaining("new_user"), 5)

    def test_remaining_decrements(self):
        self.limiter.is_allowed("user")
        self.assertEqual(self.limiter.remaining("user"), 4)
        self.limiter.is_allowed("user")
        self.assertEqual(self.limiter.remaining("user"), 3)

    def test_remaining_zero_when_limited(self):
        for _ in range(5):
            self.limiter.is_allowed("user")
        self.assertEqual(self.limiter.remaining("user"), 0)

    def test_remaining_not_negative(self):
        for _ in range(10):
            self.limiter.is_allowed("user")
        self.assertGreaterEqual(self.limiter.remaining("user"), 0)


class TestCommandRateLimiterReset(unittest.TestCase):
    """reset() clears a specific user's rate limit."""

    def setUp(self):
        self.limiter = CommandRateLimiter()

    def test_reset_allows_again(self):
        for _ in range(5):
            self.limiter.is_allowed("user")
        self.assertFalse(self.limiter.is_allowed("user"))

        self.limiter.reset("user")
        self.assertTrue(self.limiter.is_allowed("user"))

    def test_reset_only_affects_target_user(self):
        for _ in range(5):
            self.limiter.is_allowed("user_a")
        for _ in range(5):
            self.limiter.is_allowed("user_b")

        self.limiter.reset("user_a")

        self.assertTrue(self.limiter.is_allowed("user_a"))
        self.assertFalse(self.limiter.is_allowed("user_b"))

    def test_reset_nonexistent_user(self):
        # Should not raise
        self.limiter.reset("nonexistent")


class TestCommandRateLimiterCustomConfig(unittest.TestCase):
    """Custom max_commands and window_seconds."""

    def test_custom_max(self):
        limiter = CommandRateLimiter(max_commands=10, window_seconds=60)
        for _ in range(10):
            self.assertTrue(limiter.is_allowed("user"))
        self.assertFalse(limiter.is_allowed("user"))

    def test_custom_window(self):
        limiter = CommandRateLimiter(max_commands=2, window_seconds=1)
        limiter.is_allowed("user")
        limiter.is_allowed("user")
        self.assertFalse(limiter.is_allowed("user"))
        time.sleep(1.1)
        self.assertTrue(limiter.is_allowed("user"))


class TestCommandRateLimiterBlockedDoesNotRecord(unittest.TestCase):
    """When a command is blocked, it must NOT consume a slot."""

    def setUp(self):
        self.limiter = CommandRateLimiter(max_commands=3, window_seconds=60)

    def test_blocked_request_not_recorded(self):
        self.limiter.is_allowed("user")
        self.limiter.is_allowed("user")
        self.limiter.is_allowed("user")

        # These should be blocked and NOT consume slots
        self.assertFalse(self.limiter.is_allowed("user"))
        self.assertFalse(self.limiter.is_allowed("user"))

        # Remaining should still be 0 (already at limit)
        self.assertEqual(self.limiter.remaining("user"), 0)


class TestCommandRateLimiterIntegration(unittest.TestCase):
    """End-to-end: simulate spamming then recovery."""

    def test_spam_then_recovery(self):
        limiter = CommandRateLimiter(max_commands=5, window_seconds=2)

        # Simulate a user spamming /alerts
        results = [limiter.is_allowed("spammer") for _ in range(10)]
        self.assertEqual(results, [True, True, True, True, True,
                                   False, False, False, False, False])

        # Wait for window to slide
        time.sleep(2.1)

        # Should be allowed again
        self.assertTrue(limiter.is_allowed("spammer"))
        self.assertEqual(limiter.remaining("spammer"), 4)


if __name__ == "__main__":
    unittest.main()