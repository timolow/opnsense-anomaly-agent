# OPNsense Agent E2E Test Pipeline
# Spins up isolated containers, injects test data, validates entire stack

import subprocess
import time
import json
import sys
import os
from pathlib import Path
from datetime import datetime, timezone, timedelta
import psycopg2
import psycopg2.extras
import urllib.request
import urllib.error

# Configuration
BASE_DIR = Path(__file__).parent.parent
TEST_DIR = BASE_DIR / "tests"
DOCKER_COMPOSE = TEST_DIR / "docker-compose.test.yml"
TEST_URL = "http://localhost:8767"  # Test agent on port 8767
DB_HOST = "localhost"
DB_PORT = 5433
DB_NAME = "opnsense"
DB_USER = "opnsense"
DB_PASS = "testpass123"

class TestResults:
    def __init__(self):
        self.tests = []
        self.screenshots = []
    
    def add(self, name, passed, details=""):
        status = "✅ PASS" if passed else "❌ FAIL"
        self.tests.append({
            "name": name,
            "passed": passed,
            "details": details,
            "status": status
        })
        print(f"  {status} | {name}")
        if details:
            for line in details.split('\n'):
                print(f"           {line}")
    
    def summary(self):
        passed = sum(1 for t in self.tests if t['passed'])
        total = len(self.tests)
        print(f"\n{'='*60}")
        print(f"RESULTS: {passed}/{total} tests passed")
        print(f"{'='*60}")
        
        if passed < total:
            print("\nFAILED TESTS:")
            for t in self.tests:
                if not t['passed']:
                    print(f"  ❌ {t['name']}: {t['details']}")
        
        return passed == total

def run_cmd(cmd, check=True, capture=True):
    """Run a shell command."""
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=capture,
            text=True,
            timeout=60
        )
        if check and result.returncode != 0:
            print(f"Command failed: {cmd}")
            print(f"stdout: {result.stdout}")
            print(f"stderr: {result.stderr}")
            return None
        return result
    except subprocess.TimeoutExpired:
        print(f"Timeout running: {cmd}")
        return None

def wait_for_service(url, timeout=30):
    """Wait for a service to become available."""
    print(f"Waiting for service at {url}...")
    start = time.time()
    while time.time() - start < timeout:
        try:
            req = urllib.request.urlopen(url, timeout=5)
            return True
        except (urllib.error.URLError, ConnectionError, OSError):
            time.sleep(2)
    return False

def test_container_setup(results):
    """Test 1: Spin up test containers."""
    print("\n📦 STEP 1: Setting up test containers...")
    
    # Stop any existing test containers
    run_cmd(f"docker compose -f {DOCKER_COMPOSE} down --remove-orphans", check=False)
    
    # Build and start
    result = run_cmd(f"docker compose -f {DOCKER_COMPOSE} up --build -d")
    if not result:
        results.add("Container setup", False, "Failed to start containers")
        return False
    
    # Wait for services
    time.sleep(10)
    
    # Check if containers are running
    result = run_cmd("docker compose -f docker-compose.test.yml ps --format json")
    if not result:
        results.add("Containers running", False, "Containers not running")
        return False
    
    # Verify agent is accessible
    if wait_for_service(f"{TEST_URL}/health"):
        results.add("Container setup", True, "All services started successfully")
        return True
    else:
        results.add("Container setup", False, "Agent service not responding")
        # Get logs for debugging
        logs = run_cmd(f"docker compose -f {DOCKER_COMPOSE} logs agent")
        if logs:
            results.tests[-1]['details'] += f"\nLast logs:\n{logs.stdout[-500:]}"
        return False

def inject_test_data(results):
    """Test 2: Inject synthetic test data into PostgreSQL."""
    print("\n💉 STEP 2: Injecting test data...")
    
    try:
        conn = psycopg2.connect(
            host=DB_HOST,
            port=DB_PORT,
            dbname=DB_NAME,
            user=DB_USER,
            password=DB_PASS
        )
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        # Clear previous test data
        cur.execute("DELETE FROM events")
        cur.execute("DELETE FROM anomalies")
        conn.commit()
        
        now = datetime.now(timezone.utc)
        events_injected = 0
        
        # Scenario 1: Normal traffic (PASS events)
        print("  Injecting normal traffic...")
        for i in range(500):
            ts = now - timedelta(hours=23, minutes=i)
            cur.execute("""
                INSERT INTO events 
                (timestamp, src_ip, dst_ip, src_port, dst_port, proto, action, interface, raw_message)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                ts.isoformat(),
                f"192.168.1.{100 + (i % 10)}",
                f"10.0.0.{1 + (i % 5)}",
                50000 + i,
                80,
                "TCP",
                "PASS",
                "ixl3_vlan1003",
                f"Normal TCP traffic event {i}"
            ))
            events_injected += 1
        
        # Scenario 2: Blocked traffic
        print("  Injecting blocked traffic...")
        for i in range(100):
            ts = now - timedelta(hours=12, minutes=i)
            cur.execute("""
                INSERT INTO events 
                (timestamp, src_ip, dst_ip, src_port, dst_port, proto, action, interface, raw_message)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                ts.isoformat(),
                f"203.0.113.{50 + i}",
                f"192.168.1.1",
                12345,
                22,
                "TCP",
                "BLOCK",
                "ixl2",
                f"Blocked intrusion attempt {i}"
            ))
            events_injected += 1
        
        # Scenario 3: Anomalous IP scanning (50 different destinations)
        print("  Injecting IP scan anomaly...")
        scan_src = "198.51.100.77"
        for i in range(50):
            ts = now - timedelta(hours=1)
            cur.execute("""
                INSERT INTO events 
                (timestamp, src_ip, dst_ip, src_port, dst_port, proto, action, interface, raw_message)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                ts.isoformat(),
                scan_src,
                f"192.168.1.{i}",
                54321,
                80 + i,
                "TCP",
                "PASS",
                "ixl2",
                f"Scan packet {i}"
            ))
            events_injected += 1
        
        # Scenario 4: Service spike (DHCP)
        print("  Injecting service spike...")
        for i in range(200):
            ts = now - timedelta(minutes=i)
            cur.execute("""
                INSERT INTO events 
                (timestamp, src_ip, dst_ip, src_port, dst_port, proto, action, interface, raw_message)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                ts.isoformat(),
                "192.168.1.1",
                f"192.168.1.{200 + (i % 20)}",
                67,
                68,
                "UDP",
                "PASS",
                "ixl3_vlan1003",
                "DHCP request"
            ))
            events_injected += 1
        
        conn.commit()
        cur.close()
        conn.close()
        
        results.add("Data injection", True, f"Injected {events_injected} test events")
        return events_injected
        
    except Exception as e:
        results.add("Data injection", False, str(e))
        return 0

def test_api_endpoints(results, total_events):
    """Test 3: Validate all API endpoints with injected data."""
    print("\n🔌 STEP 3: Testing API endpoints...")
    
    def test_api(endpoint, expected_fields, name=""):
        try:
            url = f"{TEST_URL}{endpoint}"
            req = urllib.request.urlopen(url, timeout=10)
            data = json.loads(req.read().decode())
            
            # Check required fields
            for field in expected_fields:
                if field not in data:
                    return False, f"Missing field: {field}"
            
            return True, f"OK - {len(data)} keys"
        except Exception as e:
            return False, str(e)
    
    # Test core endpoints
    tests = [
        ("/api/stats", ["counters", "total_events", "by_severity"], "Stats"),
        ("/api/alerts", ["anomalies"], "Alerts"),
        ("/api/heatmap", ["labels_x", "labels_y", "data"], "Heatmap"),
        ("/api/ip-flow", ["nodes", "links"], "IP Flow"),
        ("/api/events", [], "Events (empty response expected)"),
        ("/api/pfelk/traffic-flow", ["nodes", "links"], "PFELK Traffic"),
        ("/api/pfelk/protocols", ["protocols"], "PFELK Protocols"),
        ("/api/pfelk/actions", ["actions"], "PFELK Actions"),
        ("/api/pfelk/timeline", ["timeline"], "PFELK Timeline"),
    ]
    
    for endpoint, fields, name in tests:
        passed, details = test_api(endpoint, fields, name)
        results.add(f"API: {name}", passed, details)
    
    # Test data integrity
    try:
        req = urllib.request.urlopen(f"{TEST_URL}/api/stats", timeout=10)
        stats = json.loads(req.read().decode())
        
        # Verify total events
        total_from_api = stats.get('total_events', 0)
        if total_from_api > 0:
            results.add(
                "Data integrity",
                total_from_api >= total_events * 0.9,
                f"API reports {total_from_api} events (expected ~{total_events})"
            )
        else:
            results.add("Data integrity", False, "API reports 0 events")
    except Exception as e:
        results.add("Data integrity", False, str(e))
    
    return True

def test_visual_verification(results):
    """Test 4: Headless browser visual verification."""
    print("\n📸 STEP 4: Visual verification with Playwright...")
    
    # Check if Playwright is installed
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        results.add("Playwright", False, "Playwright not installed - skipping visual tests")
        print("  Install with: npx playwright install")
        return False
    
    screenshots_dir = TEST_DIR / "screenshots"
    screenshots_dir.mkdir(exist_ok=True)
    
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(
            viewport={'width': 1280, 'height': 900}
        )
        page = context.new_page()
        
        # Test all tabs
        tabs_to_test = [
            ("#overview", "Overview"),
            ("#pfelk", "PFELK Analytics"),
            ("#heatmap", "Heatmap"),
            ("#alerts", "Alerts"),
        ]
        
        for hash_val, tab_name in tabs_to_test:
            try:
                url = f"{TEST_URL}/?t={int(time.time())}{hash_val}"
                print(f"  Testing {tab_name}...")
                
                page.goto(url, wait_until="networkidle", timeout=30000)
                
                # Wait for content to render
                time.sleep(3)
                
                # Check for JS errors
                js_errors = page.evaluate("""
                    () => {
                        const errors = [];
                        window.addEventListener('error', (e) => errors.push(e.message));
                        return errors;
                    }
                """)
                
                if js_errors:
                    results.add(
                        f"UI: {tab_name}",
                        False,
                        f"JS errors: {', '.join(js_errors)}"
                    )
                else:
                    # Take screenshot
                    screenshot_path = screenshots_dir / f"{tab_name.lower().replace(' ', '-')}.png"
                    page.screenshot(path=str(screenshot_path), full_page=True)
                    
                    # Verify page has content
                    body_text = page.inner_text('body')
                    if body_text and len(body_text) > 50:
                        results.add(
                            f"UI: {tab_name}",
                            True,
                            f"Screenshot saved, content length: {len(body_text)} chars"
                        )
                    else:
                        results.add(
                            f"UI: {tab_name}",
                            False,
                            "Page appears empty"
                        )
            
            except Exception as e:
                results.add(f"UI: {tab_name}", False, str(e))
        
        browser.close()
    
    results.screenshots = list(screenshots_dir.glob("*.png"))
    return True

def test_alert_logic(results):
    """Test 5: Verify alert/anomaly detection logic."""
    print("\n🚨 STEP 5: Testing alert logic...")
    
    try:
        # Check anomalies were detected for scan activity
        req = urllib.request.urlopen(f"{TEST_URL}/api/alerts", timeout=10)
        alerts = json.loads(req.read().decode())
        
        anomalies = alerts.get('anomalies', [])
        
        # Should have detected IP scanning
        scan_detected = any(
            'scan' in str(a).lower() or 
            'anomaly' in str(a).lower() or 
            'unusual' in str(a).lower()
            for a in anomalies
        )
        
        results.add(
            "Anomaly detection",
            scan_detected,
            f"Found {len(anomalies)} anomalies in test data"
        )
        
        # Check severity distribution
        req = urllib.request.urlopen(f"{TEST_URL}/api/stats", timeout=10)
        stats = json.loads(req.read().decode())
        
        severity = stats.get('by_severity', {})
        if severity.get('CRITICAL', 0) > 0 or severity.get('HIGH', 0) > 0:
            results.add(
                "Severity classification",
                True,
                f"CRITICAL: {severity.get('CRITICAL')}, HIGH: {severity.get('HIGH')}"
            )
        else:
            results.add(
                "Severity classification",
                False,
                "No CRITICAL or HIGH anomalies detected"
            )
        
        return True
        
    except Exception as e:
        results.add("Alert logic", False, str(e))
        return False

def test_interaction(results):
    """Test 6: Test UI interactions."""
    print("\n🖱️  STEP 6: Testing UI interactions...")
    
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        results.add("Interactions", False, "Playwright not installed")
        return False
    
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        
        try:
            url = f"{TEST_URL}/?t={int(time.time())}"
            page.goto(url, wait_until="networkidle", timeout=30000)
            time.sleep(2)
            
            # Test sidebar navigation
            sidebar_buttons = page.locator('.sidebar button').count()
            results.add(
                "Sidebar navigation",
                sidebar_buttons > 5,
                f"Found {sidebar_buttons} navigation buttons"
            )
            
            # Test scrolling
            page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
            scrolled_height = page.evaluate("window.scrollY")
            results.add(
                "Page scrolling",
                scrolled_height > 500,
                f"Scroll position: {scrolled_height}px"
            )
            
            # Test navigation to different tabs
            try:
                # Click PFELK tab
                pfelk_tab = page.locator('text=PFELK Analytics').first
                if pfelk_tab.is_visible():
                    pfelk_tab.click()
                    time.sleep(2)
                    current_url = page.url
                    results.add(
                        "Tab navigation",
                        'pfelk' in current_url or 'pfelk' in page.title().lower(),
                        f"Navigation to PFELK successful"
                    )
                else:
                    results.add("Tab navigation", False, "PFELK tab not found")
            except Exception as e:
                results.add("Tab navigation", False, str(e))
            
        finally:
            browser.close()
    
    return True

def main():
    """Main E2E test pipeline."""
    print("="*60)
    print("OPNsense Agent E2E Test Pipeline")
    print("="*60)
    
    results = TestResults()
    total_injected = 0
    
    try:
        # Step 1: Setup containers
        if not test_container_setup(results):
            print("\n❌ Container setup failed. Aborting tests.")
            results.summary()
            return 1
        
        # Step 2: Inject test data
        total_injected = inject_test_data(results)
        
        # Step 3: Test API endpoints
        test_api_endpoints(results, total_injected)
        
        # Step 4: Visual verification
        test_visual_verification(results)
        
        # Step 5: Alert logic
        test_alert_logic(results)
        
        # Step 6: UI interactions
        test_interaction(results)
        
        # Print results
        all_passed = results.summary()
        
        # Show screenshots
        if results.screenshots:
            print(f"\n📸 Screenshots saved to {TEST_DIR}/screenshots/")
            for s in results.screenshots:
                print(f"   {s.name}")
        
        return 0 if all_passed else 1
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Tests interrupted by user")
        return 1
    
    finally:
        # Cleanup: stop containers
        print("\n🧹 Cleaning up test containers...")
        run_cmd(f"docker compose -f {DOCKER_COMPOSE} down --remove-orphans", check=False)

if __name__ == "__main__":
    sys.exit(main())
