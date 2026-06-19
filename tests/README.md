# OPNsense Agent E2E Test Suite
# Spins up isolated containers, injects synthetic data, validates all functionality

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│  E2E Test Orchestrator (test_e2e_pipeline.py)           │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────────┐ │
│  │ Container    │  │ Data         │  │ Visual         │ │
│  │ Setup        │  │ Injection    │  │ Verification   │ │
│  └─────────────┘  └──────────────┘  └────────────────┘ │
│         │                │                │             │
│         ▼                ▼                ▼             │
│  ┌──────────────────────────────────────────────────┐  │
│  │  Parallel Verification                           │  │
│  │  ├─ API Tests (17 endpoints)                     │  │
│  │  ├─ Data Integrity (aggregations, time ranges)   │  │
│  │  ├─ Alert Logic (classification, notifications)  │  │
│  │  ├─ UI Rendering (screenshots, element checks)   │  │
│  │  └─ Interaction Tests (navigation, forms)        │  │
│  └──────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

## Components

### 1. `tests/docker-compose.test.yml`
- Isolated PostgreSQL container
- Test Redis (optional)
- Agent + WebUI with test config
- Data volume for synthetic data

### 2. `tests/test_e2e_data_injection.py`
- Inserts synthetic events into PostgreSQL
- Tests various scenarios:
  - Normal traffic (PASS events)
  - Blocked traffic (BLOCK events)
  - Anomalous patterns (IP scanning, port sweeps)
  - Service detection (new services, service spikes)
  - IDS signatures
  - ZenArmor events
  - OPNsense configuration changes

### 3. `tests/test_e2e_api.py`
- Validates all API endpoints
- Checks data types, structure, ranges
- Tests cache behavior
- Validates aggregated metrics

### 4. `tests/test_e2e_visual.py`
- Headless browser tests (Playwright)
- Screenshots of all tabs
- Visual element verification
- Interaction testing (click, scroll, form input)

### 5. `tests/test_e2e_pipeline.py`
- Orchestrator that runs all tests
- Spins up containers, injects data, runs tests, tears down
- Generates test report with results and screenshots

### 6. GitHub Actions Integration
- `.github/workflows/e2e-tests.yml`
- Runs on PR, merge, and schedule
- Uploads screenshots as artifacts

## Running Tests

```bash
# Full E2E test suite
python3 tests/test_e2e_pipeline.py

# Specific test file
python3 tests/test_e2e_data_injection.py
python3 tests/test_e2e_api.py
python3 tests/test_e2e_visual.py

# With Docker Compose
docker compose -f tests/docker-compose.test.yml up --build
```

## Test Scenarios

### Scenario 1: Normal Traffic
- Inject 1000 PASS events over 24 hours
- Verify: 1000 events in DB, 1000 in API, 1000 on UI

### Scenario 2: Blocked Traffic
- Inject 100 BLOCK events
- Verify: 100 blocked count, action distribution chart shows ~10%

### Scenario 3: IP Scanning Anomaly
- Inject 50 events from same source to 50 different destinations
- Verify: Anomaly detected, severity HIGH/CRITICAL, alert generated

### Scenario 4: New Service Detection
- Inject events for services not in KNOWN_SERVICES
- Verify: NEW_SERVICE anomaly, alert sent (or logged in test mode)

### Scenario 5: Service Spike
- Inject 1000 DHCP events in 1 minute
- Verify: SERVICE_SPIKE anomaly detected

### Scenario 6: IDS Signatures
- Inject events matching IDS signature patterns
- Verify: Signature triggered, counts updated

### Scenario 7: Full Navigation
- Verify all 18+ tabs load without errors
- Verify charts render (canvas/Recharts)
- Verify tables have data
- Verify interactive elements (mute button, search forms)
