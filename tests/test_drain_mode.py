#!/usr/bin/env python3
"""Tests for drain mode / zero-downtime deployment features.

Tests drain.py (standalone module) and deploy.sh logic.
Does NOT import server.py to avoid psycopg2 dependency in test env.
"""

import json
import subprocess
import threading
import time
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent

class TestDrainModeFunctions(unittest.TestCase):
    """Test drain mode module-level functions in drain.py."""

    def setUp(self):
        import drain
        drain.reset_drain_state()

    def tearDown(self):
        import drain
        drain.reset_drain_state()

    def test_drain_initially_off(self):
        import drain
        self.assertFalse(drain.is_draining())
        self.assertEqual(drain.get_active_request_count(), 0)

    def test_enter_drain_mode(self):
        import drain
        drain.enter_drain_mode()
        self.assertTrue(drain.is_draining())
        self.assertIsInstance(drain._drain_initiated_at, float)
        self.assertGreater(drain._drain_initiated_at, 0)

    def test_request_enter_exit(self):
        import drain
        drain._request_enter()
        self.assertEqual(drain.get_active_request_count(), 1)
        drain._request_enter()
        self.assertEqual(drain.get_active_request_count(), 2)
        drain._request_exit()
        self.assertEqual(drain.get_active_request_count(), 1)
        drain._request_exit()
        self.assertEqual(drain.get_active_request_count(), 0)

    def test_drain_waits_for_zero_requests(self):
        import drain
        drain.enter_drain_mode()
        # No active requests should drain immediately
        drained = drain.wait_for_drain(timeout=1)
        self.assertTrue(drained)

    def test_drain_waits_with_active_requests(self):
        import drain
        drain.enter_drain_mode()
        drain._request_enter()  # Simulate active request
        self.assertEqual(drain.get_active_request_count(), 1)

        # Drain should block... simulate request completing in background
        def release():
            time.sleep(0.3)
            drain._request_exit()

        t = threading.Thread(target=release)
        t.start()

        drained = drain.wait_for_drain(timeout=5)
        t.join()
        self.assertTrue(drained)
        self.assertEqual(drain.get_active_request_count(), 0)

    def test_drain_timeout(self):
        import drain
        drain.enter_drain_mode()
        drain._request_enter()  # Simulate stuck request
        # Don't release — should timeout
        drained = drain.wait_for_drain(timeout=0.5)
        self.assertFalse(drained)
        drain._request_exit()

    def test_drained_event_set_on_zero(self):
        import drain
        drain.enter_drain_mode()
        drain._request_enter()
        # Event should NOT be set yet
        self.assertFalse(drain._drained_event.is_set())
        # Release request
        drain._request_exit()
        # Event should now be set
        self.assertTrue(drain._drained_event.is_set())

    def test_graceful_shutdown(self):
        import drain
        # Test it doesn't crash
        drain.graceful_shutdown(timeout=0.5)
        self.assertTrue(drain.is_draining())

    def test_graceful_shutdown_idempotent(self):
        import drain
        drain.graceful_shutdown(timeout=0.5)
        drain.graceful_shutdown(timeout=0.5)  # Should not crash
        self.assertTrue(drain.is_draining())

    def test_reset_drain_state(self):
        import drain
        drain.enter_drain_mode()
        drain._request_enter()
        drain.reset_drain_state()
        self.assertFalse(drain.is_draining())
        self.assertEqual(drain.get_active_request_count(), 0)

    def test_concurrent_request_tracking(self):
        """Thread safety: multiple threads entering/exiting concurrently."""
        import drain
        errors = []

        def worker():
            try:
                for _ in range(50):
                    drain._request_enter()
                    time.sleep(0.001)
                    drain._request_exit()
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(drain.get_active_request_count(), 0, "Should be back to zero")
        self.assertEqual(len(errors), 0, f"Errors: {errors}")


class TestDrainModuleAPI(unittest.TestCase):
    """Test that drain.py exports all expected symbols."""

    def test_all_symbols_exist(self):
        import drain
        expected = [
            '_drain_mode', '_active_requests', '_active_requests_lock',
            '_drained_event', '_drain_initiated_at', '_MAX_DRAIN_WAIT',
            'enter_drain_mode', 'is_draining', 'get_active_request_count',
            'wait_for_drain', 'graceful_shutdown', '_request_enter',
            '_request_exit', 'reset_drain_state',
        ]
        for name in expected:
            self.assertTrue(hasattr(drain, name), f"Missing: {name}")


class TestDeployScript(unittest.TestCase):
    """Test deploy.sh logic (parse + static checks, no docker needed)."""

    def test_deploy_script_syntax(self):
        """deploy.sh should have valid bash syntax."""
        result = subprocess.run(
            ["bash", "-n", "deploy.sh"],
            capture_output=True, text=True,
            cwd=str(PROJECT_ROOT)
        )
        self.assertEqual(result.returncode, 0, f"Syntax error in deploy.sh: {result.stderr}")

    def test_rollback_script_syntax(self):
        """rollback.sh should have valid bash syntax."""
        result = subprocess.run(
            ["bash", "-n", "rollback.sh"],
            capture_output=True, text=True,
            cwd=str(PROJECT_ROOT)
        )
        self.assertEqual(result.returncode, 0, f"Syntax error in rollback.sh: {result.stderr}")

    def test_deploy_script_has_drain_step(self):
        """deploy.sh should contain a drain step."""
        with open(PROJECT_ROOT / "deploy.sh") as f:
            content = f.read()
        self.assertIn("/api/drain", content)
        self.assertIn("Draining old container", content)

    def test_deploy_script_has_rollback(self):
        """deploy.sh should have automatic rollback on failure."""
        with open(PROJECT_ROOT / "deploy.sh") as f:
            content = f.read()
        self.assertIn("Automatic rollback", content)

    def test_deploy_script_has_health_check(self):
        """deploy.sh should check health before and after."""
        with open(PROJECT_ROOT / "deploy.sh") as f:
            content = f.read()
        self.assertIn("check_health_url", content)
        self.assertIn("Staging container healthy", content)
        self.assertIn("Production container healthy", content)

    def test_deploy_state_gitignored(self):
        """deploy_state.json should be in .gitignore."""
        with open(PROJECT_ROOT / ".gitignore") as f:
            content = f.read()
        self.assertIn("deploy_state.json", content)

    def test_rollback_script_has_state_file(self):
        """rollback.sh should use deploy_state.json."""
        with open(PROJECT_ROOT / "rollback.sh") as f:
            content = f.read()
        self.assertIn("deploy_state.json", content)

    def test_drain_module_exists(self):
        """drain.py should exist and be importable."""
        result = subprocess.run(
            ["python3", "-c", "import drain; print('OK')"],
            capture_output=True, text=True,
            cwd=str(PROJECT_ROOT)
        )
        self.assertEqual(result.returncode, 0, f"drain.py import failed: {result.stderr}")

    def test_server_imports_drain(self):
        """server.py should import from drain module."""
        with open(PROJECT_ROOT / "server.py") as f:
            content = f.read()
        self.assertIn("from drain import", content)

    def test_agent_calls_shutdown_server(self):
        """agent.py should call shutdown_server during shutdown."""
        with open(PROJECT_ROOT / "agent.py") as f:
            content = f.read()
        self.assertIn("shutdown_server", content)

    def test_server_has_shutdown_server(self):
        """server.py should export shutdown_server function."""
        with open(PROJECT_ROOT / "server.py") as f:
            content = f.read()
        self.assertIn("def shutdown_server", content)

    def test_health_endpoint_has_drain_fields(self):
        """query_health in server.py should include drain status."""
        with open(PROJECT_ROOT / "server.py") as f:
            content = f.read()
        self.assertIn('"draining": is_draining()', content)
        self.assertIn('"active_requests": get_active_request_count()', content)


if __name__ == "__main__":
    unittest.main()