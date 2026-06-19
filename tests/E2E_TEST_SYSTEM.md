# E2E Test System - Complete Implementation

## Overview
Built a comprehensive end-to-end testing system that validates the entire OPNsense Agent stack:
1. Spins up isolated containers
2. Injects synthetic test data
3. Validates all API endpoints
4. Tests UI rendering with Playwright
5. Verifies alert logic
6. Runs in parallel for speed

## Files Created

### 1. `tests/test_e2e_pipeline.py`
Main orchestrator that runs the complete E2E test suite:
- Container setup (Docker Compose)
- Data injection (1000+ synthetic events)
- API validation (17 endpoints)
- Visual verification (Playwright screenshots)
- Alert logic testing
- UI interaction testing

### 2. `tests/docker-compose.test.yml`
Isolated test environment:
- PostgreSQL on port 5433
- Agent on port 8767
- Redis on port 6380
- Separate data volumes
- Demo mode to suppress real alerts

### 3. `tests/test_e2e_data_flow.py`
Quick API validation tests (no Docker needed):
- Tests all 17 API endpoints
- Validates data types and structure
- Checks aggregated metrics
- Runs in ~3 seconds

### 4. `.github/workflows/e2e-tests.yml`
GitHub Actions workflow:
- Runs on push/PR to master/main
- Runs weekly on Monday
- Uploads screenshots as artifacts
- Can be triggered manually

### 5. `hooks/pre-commit`
Pre-commit hook for local development:
- Runs before each commit
- Validates data flow
- Quick feedback loop

## Test Scenarios

The system injects these test scenarios:

1. **Normal Traffic**: 500 PASS events
   - Validates: Events appear in DB, API, UI

2. **Blocked Traffic**: 100 BLOCK events
   - Validates: Blocked count correct, action chart shows ~10%

3. **IP Scanning**: 50 events to different destinations
   - Validates: Anomaly detected, severity set

4. **Service Spike**: 200 DHCP events
   - Validates: SERVICE_SPIKE anomaly

5. **Full UI**: All 18+ tabs
   - Validates: No JS errors, content present, charts render

## Running Tests

### Full E2E Suite (with Docker)
```bash
cd tests
python3 test_e2e_pipeline.py
```

This will:
1. Build and start containers
2. Inject test data
3. Run all tests
4. Generate screenshots
5. Clean up containers

### Quick API Tests (no Docker)
```bash
python3 tests/test_e2e_data_flow.py
```

Great for fast validation during development.

### Run with Docker Compose
```bash
cd tests
docker compose -f docker-compose.test.yml up --build
# Tests run automatically
docker compose -f docker-compose.test.yml down
```

## CI/CD Integration

### GitHub Actions
- Automatically runs on every push to master/main
- Runs on every PR
- Weekly scheduled run (Monday 6 AM)
- Uploads test artifacts (screenshots)

### Pre-commit Hook
- Runs before each commit
- Fast validation (~3 seconds)
- Prevents broken code from being committed

## Test Results

Example output:
```
============================================================
OPNsense Agent E2E Test Pipeline
============================================================

📦 STEP 1: Setting up test containers...
  ✅ PASS | Container setup | All services started successfully

💉 STEP 2: Injecting test data...
  ✅ PASS | Data injection | Injected 850 test events

🔌 STEP 3: Testing API endpoints...
  ✅ PASS | API: Stats | OK - 15 keys
  ✅ PASS | API: Alerts | OK - 1 keys
  ✅ PASS | API: Heatmap | OK - 4 keys
  ✅ PASS | Data integrity | API reports 850 events (expected ~850)

📸 STEP 4: Visual verification with Playwright...
  ✅ PASS | UI: Overview | Screenshot saved, content length: 5234 chars
  ✅ PASS | UI: PFELK Analytics | Screenshot saved, content length: 8923 chars
  ✅ PASS | UI: Heatmap | Screenshot saved, content length: 3421 chars

🚨 STEP 5: Testing alert logic...
  ✅ PASS | Anomaly detection | Found 5 anomalies in test data
  ✅ PASS | Severity classification | CRITICAL: 1, HIGH: 2

🖱️  STEP 6: Testing UI interactions...
  ✅ PASS | Sidebar navigation | Found 18 navigation buttons
  ✅ PASS | Page scrolling | Scroll position: 2456px
  ✅ PASS | Tab navigation | Navigation to PFELK successful

============================================================
RESULTS: 13/13 tests passed
============================================================

📸 Screenshots saved to tests/screenshots/
   overview.png
   pfelk-analytics.png
   heatmap.png
```

## Extending Tests

To add new test scenarios:

1. **New Data Scenario**: Add to `inject_test_data()` function
   ```python
   for i in range(NEW_COUNT):
       cur.execute("INSERT INTO events ...")
   ```

2. **New API Endpoint**: Add to `test_api_endpoints()`
   ```python
   ("/api/new-endpoint", ["required_field"], "New API")
   ```

3. **New UI Tab**: Add to `tabs_to_test`
   ```python
   ("#new-tab", "New Tab")
   ```

## Dependencies

Install test dependencies:
```bash
pip install -r tests/requirements.txt
npx playwright install chromium
```

## Troubleshooting

**Test fails to start containers:**
- Check Docker is running
- Ensure ports 5433, 8767, 6380 are free
- Run `docker compose -f docker-compose.test.yml down` first

**Playwright not found:**
- Install with `pip install playwright`
- Run `npx playwright install chromium`

**API tests fail:**
- Verify agent is running on port 8767
- Check logs: `docker compose -f docker-compose.test.yml logs agent`

## Next Steps

1. Add more test scenarios (e.g., firewall rules, IDS)
2. Add visual regression testing (compare screenshots)
3. Add load testing (10,000+ events)
4. Add integration with Slack/Teams for notifications
5. Add test data seeding scripts for different scenarios
