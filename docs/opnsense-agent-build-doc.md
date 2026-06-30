# OPNsense Anomaly Agent — Build & E2E Verification Documentation

## Project Overview

**OPNsense Anomaly Agent** is a syslog-based ML anomaly detection system with Discord alerting, state persistence, and an embedded React dashboard.

- **Repository**: `~/opnsense-anomaly-agent/` (public GitHub)
- **Deployment**: 192.168.1.50 (tim@, SSH key), Docker container `anomaly-agent`
- **Dashboard**: http://192.168.1.50:8766
- **OPNsense**: Business 26.4, API port 6666, self-signed cert, FreeBSD 14.3, multi-WAN
- **GitHub**: master branch. PAT: `GH_TOKEN` env var.

---

## E2E Verification Framework

### Architecture

The E2E framework consists of **6 modules** that trace data from source to UI:

```
Source (syslog/OPNsense API)
  |
  v
[test_data_seeder] --> Injects marker data (192.168.100.x)
  |
  v
pipeline_verification --> 8-stage source-to-UI trace
  |
  v
+-- api_verification --> All API endpoints (26+ endpoints, ~210 checks)
+-- empty_state_verification --> Per-tab empty-state messaging (26 tabs)
+-- ui_verification --> Playwright UI rendering (19 tabs, 97 checks)
  |
  v
e2e_reporter --> Orchestrator: consolidated JSON report
  |
  v
kanban_e2e_hook --> Gates kanban task completion on failures
```

### Modules

#### 1. `test_data_seeder.py` — Test Data Injection

Injects identifiable test records with marker IPs (192.168.100.x) so E2E tests verify source -> DB -> API -> UI flow without touching production data.

**Marker IPs (16 total, 192.168.100.x range):**

| Marker IP | Scenario |
|-----------|----------|
| .1 | Normal TCP traffic |
| .2 | Normal UDP traffic |
| .10 | Port scan |
| .11 | SYN flood |
| .12 | Brute force SSH |
| .20 | XMAS probe |
| .21 | NULL probe |
| .22 | FIN probe |
| .50 | High volume |
| .60 | WAN outbound |
| .70 | LAN internal |
| .80 | ZenArmor |
| .81 | IDS trigger |
| .82 | Nginx web |
| .90 | Service DHCP |
| .99 | WAN flap |

**Seeding API:**

```python
from test_data_seeder import TestSeeder
seeder = TestSeeder()
counts = seeder.seed_all(hours_ago=1.0)    # All tables
counts = seeder.seed_mixed(hours_ago=1.0)  # Realistic mix
seeder.cleanup()                            # Remove all test data
```

**Seeded data types (10 anomaly types, 5 log types):**
- Events: filterlog, zenarmor, ids, nginx, system
- Anomalies: all attack types covered
- Baselines, drift events, threat profiles, rule baselines, rule feedback

**Cleanup:** Deletes by marker IP range (192.168.100.%) and TEST_SEED prefix — safe to run alongside production data.

#### 2. `pipeline_verification.py` — Source-to-UI Tracing (8 Stages)

Traces data flow end-to-end through the entire anomaly detection pipeline.

**8 Stages verified:**

| Stage | What it checks | Key endpoints |
|-------|---------------|---------------|
| SOURCE | Health endpoint, DB connectivity, syslog listener, OPNsense API, version, resources | /api/health, /api/version, /api/resources |
| PARSER | Required fields (timestamp, src_ip, dst_ip, proto, action), optional fields, log_type classification, ISO 8601 timestamps | /api/events |
| AGENT | Event ingestion count, multi-source routing, stats freshness (<5min), ML rule classification, active learning queue | /api/stats, /api/ml-summary, /api/active-learning-queue |
| DATABASE | Schema version, events persistence with IDs, pipeline latency (ingested_at vs timestamp), marker data integrity | /api/schema-migrations, /api/events |
| ANOMALY | Attack detection triggers on seeded data, geo anomaly detection | /api/anomalies, /api/alerts |
| BASELINE | Baseline engine stores rule_baselines, drift detection, threshold tuning | /api/baselines, /api/drift |
| API | REST endpoints return seeded data with correct structure | All API endpoints |
| UI_DATA | Frontend-data contracts (API -> UI field mapping) | Cross-references UI tab specs |

**Usage:**

```bash
python3 pipeline_verification.py                                # All stages
python3 pipeline_verification.py --base http://192.168.1.50:8766 # Remote
python3 pipeline_verification.py --stage database               # Single stage
python3 pipeline_verification.py --json                         # Machine-readable
python3 pipeline_verification.py --dry-run                      # Plan only
```

**Exit codes:** 0 = all stages healthy, 1 = one or more stages have issues.

#### 3. `api_verification.py` — API Endpoint Verification

Hits every dashboard API endpoint and verifies:
1. HTTP status (200/401 expected, 4xx/5xx flagged)
2. JSON parsability
3. Required structural keys present
4. Data presence (distinguishes expected empty from pipeline failure)
5. Error handling (invalid params return structured errors, not crashes)

**Endpoint categories:**
- Core health: /api/health, /api/stats, /api/version, /api/heartbeat, /api/resources, /api/metrics
- Visualization: /api/heatmap, /api/ip-flow, /api/traffic-flow, /api/geo
- Threat: /api/alerts, /api/anomalies, /api/mutes, /api/zenarmor*, /api/ids*
- System: /api/opnsense, /api/services, /api/service-status, /api/nginx*, /api/wan-flap
- Rules: /api/rules, /api/rules-classified, /api/ml-summary
- Logs: /api/events, /api/system_logs
- Network: /api/ip-flow-clusters, /api/protocols

**Usage:**

```bash
python3 api_verification.py --base http://192.168.1.50:8766
python3 api_verification.py --dry-run
python3 api_verification.py --verbose
```

#### 4. `empty_state_verification.py` — Empty State Messaging Validation

Checks all 26 API endpoints for proper empty-state messaging. Catches:
- Tabs showing "0" without explaining WHAT the zero means
- Tabs not distinguishing "no data yet" from "data source not configured"
- Tabs crashing or returning malformed responses when empty

**DataSourceStatus levels:**

| Status | Meaning |
|--------|---------|
| CONFIGURED | Data source wired up, data flows |
| NO_DATA | Configured but no events collected yet |
| NOT_CONFIGURED | Missing credentials/endpoint/setup |
| UNKNOWN | Cannot determine status from response |

**26 tabs/endpoints covered:**

| Tab | Endpoint | Expected empty status | Empty message |
|-----|----------|----------------------|---------------|
| Overview | /api/stats | NO_DATA | "No events collected yet..." |
| Traffic Heatmap | /api/heatmap | NO_DATA | "No traffic data yet..." |
| Flow Map | /api/ip-flow | NO_DATA | "No flow data yet..." |
| IP Flow | /api/ip-flow | NO_DATA | "No IP flow data..." |
| IP Flow Clusters | /api/ip-flow-clusters | NO_DATA | "No cluster data yet..." |
| Threat Alerts | /api/alerts | NO_DATA | "No alerts detected..." |
| Threat Alerts (ML) | /api/anomalies | NO_DATA | "No anomalies detected..." |
| Mutes | /api/mutes | NO_DATA | "No active mutes..." |
| ZenArmor | /api/zenarmor-summary | NO_DATA | "No ZenArmor events..." |
| ZenArmor Policies | /api/zenarmor-policies | NO_DATA | "No ZenArmor policies..." |
| IDS | /api/ids-summary | NO_DATA | "No IDS events..." |
| IDS Signatures | /api/ids-signatures | NO_DATA | "No IDS signatures..." |
| Geography | /api/geo | NO_DATA | "No geographic data yet..." |
| OPNsense Status | /api/opnsense | NOT_CONFIGURED | "OPNsense API not configured..." |
| Firewall Rules | /api/rules-classified | NO_DATA | "No firewall rules loaded..." |
| Rules ML | /api/rules-classified | NO_DATA | "No classified rules..." |
| Syslogs | /api/events | NO_DATA | "No events logged yet..." |
| Services | /api/service-status | NO_DATA | "No services monitored yet..." |
| Query Logs | /api/events | NO_DATA | "No logs to query..." |
| Network Topology | /api/ip-flow | NO_DATA | "No network topology data..." |
| WAN Flap | /api/wan-flap | NO_DATA | "No WAN flaps detected..." |
| Nginx Monitor | /api/nginx-summary | NOT_CONFIGURED | "No Nginx stub_status endpoint..." |
| Nginx Anomalies | /api/nginx-anomalies | NOT_CONFIGURED | "No Nginx anomaly data..." |
| Traffic Flow | /api/traffic-flow | NO_DATA | "No traffic flow data..." |
| Protocol Distribution | /api/protocols | NO_DATA | "No protocol data..." |
| System Health | /api/health | CONFIGURED | Always returns data |

**Usage:**

```bash
python3 empty_state_verification.py --base http://192.168.1.50:8766
python3 empty_state_verification.py --json
python3 empty_state_verification.py --verbose
```

#### 5. `ui_verification.py` — Playwright UI Rendering Verification

Navigates all 19 dashboard tabs via Playwright and verifies:
1. Correct heading/title renders for the active tab
2. No "Tab Crashed" error boundary visible
3. No "Data Error" / "Connection Error" banners
4. Actual data content visible (stat cards, tables, charts)
5. Zero uncaught JavaScript errors in console
6. Empty state messages when applicable
7. Sidebar active state matches current tab

**19 Dashboard Tabs:**

| # | Tab | Hash | Expected Title | API Endpoints | Empty OK? |
|---|-----|------|----------------|---------------|-----------|
| 1 | Overview | #overview | Overview | /api/stats, /api/events | No |
| 2 | Heatmap | #heatmap | Traffic Heatmap | /api/heatmap | Yes |
| 3 | Flow Map | #flows | Flow Map | /api/ip-flow, /api/traffic-flow | Yes |
| 4 | IP Flow | #ipflow | IP Flow | /api/ip-flow | Yes |
| 5 | Geography | #geo | Geography | /api/geo | Yes |
| 6 | Alerts | #alerts | Threat Alerts | /api/alerts | Yes |
| 7 | Mutes | #mutes | Mutes | /api/mutes | Yes |
| 8 | ZenArmor | #zenarmor | ZenArmor | /api/zenarmor | Yes |
| 9 | IDS | #ids | IDS | /api/ids | Yes |
| 10 | OPNsense | #opnsense | OPNsense Status | /api/opnsense | No |
| 11 | Services | #services | Services | /api/services | Yes |
| 12 | Nginx | #nginx | Nginx Monitor | /api/nginx | Yes |
| 13 | Network | #network | Network Topology | /api/ip-flow-clusters | Yes |
| 14 | WAN Flap | #wan-flap | WAN Flap Detection | /api/wan-flap | Yes |
| 15 | Firewall Rules | #rules | Firewall Rules | /api/rules | No |
| 16 | Rules ML | #rules-classified | Rules ML | /api/rules-classified | Yes |
| 17 | Query Logs | #logs | Query Logs | /api/events | Yes |
| 18 | Syslogs | #syslogs | Syslogs | /api/system_logs | Yes |
| 19 | Settings | #settings | Settings | /api/health | No |

**Checks per tab (5 per tab = 97 total checks across 19 tabs):**
- Heading check: Correct h1 title
- No crash: No "Tab Crashed" error boundary
- No data error: No "Data Error" / "Connection Error" banners
- Content present: stat cards, tables, charts, or valid empty state
- Console errors: Zero uncaught JavaScript errors

**Usage:**

```bash
python3 ui_verification.py --base http://192.168.1.50:8766
python3 ui_verification.py --screenshot-on fail    # Only screenshot failures
python3 ui_verification.py --dry-run                # Print plan only
```

**Requires:** Playwright (`pip install playwright && playwright install chromium`)

#### 6. `e2e_reporter.py` — Orchestrator & Consolidated Report

Orchestrates all modules into a single structured JSON report.

**Report structure (JSON):**

```json
{
  "report": {
    "generated_at": "ISO-8601",
    "base_url": "target URL",
    "duration_seconds": 0.0,
    "overall_status": "PASS"
  },
  "pipeline_health": {
    "status": "healthy",
    "subsystems": { "health_endpoint": {...}, "stats": {...}, "resources": {...} }
  },
  "test_data": {
    "seeded": false,
    "cleaned": false
  },
  "api_verification": {
    "summary": { "total": N, "passed": N, "warnings": N, "failures": N, "skipped": N },
    "results": [...]
  },
  "empty_state_verification": {
    "summary": { "total": N, "pass": N, "warn": N, "fail": N },
    "results": [...]
  },
  "ui_verification": {
    "summary": { "total": N, "passed": N, "warnings": N, "failures": N, "skipped": N },
    "results": [...]
  },
  "per_tab_status": {
    "TabName": { "api": "PASS", "empty_state": "PASS", "ui": "PASS" }
  },
  "issues": [
    { "module": "api_verification", "severity": "FAIL", "message": "..." }
  ],
  "summary": {
    "total_checks": N,
    "passed": N,
    "warnings": N,
    "failures": N,
    "skipped": N,
    "overall": "PASS"
  }
}
```

**Usage:**

```bash
# Full report (JSON to stdout)
python3 e2e_reporter.py

# With test data seeding + cleanup
python3 e2e_reporter.py --seed --clean

# Write JSON report to file
python3 e2e_reporter.py --output e2e-report.json

# Run against remote deployment
python3 e2e_reporter.py --base http://192.168.1.50:8766

# Skip UI verification (~30s faster, no Playwright needed)
python3 e2e_reporter.py --skip-ui

# Skip specific modules
python3 e2e_reporter.py --skip-api
python3 e2e_reporter.py --skip-empty-state

# Verbose: print progress as it runs
python3 e2e_reporter.py --verbose
```

**Exit codes:** 0 = all checks passed, 1 = one or more checks failed.

#### 7. `kanban_e2e_hook.py` — Kanban Completion Gate

Integrates E2E verification into kanban task completion workflow. Workers call `E2ECompletionGate` before `kanban_complete()`. If E2E fails, the gate returns structured failure info for the worker to `kanban_block()` with.

**Usage from a kanban worker:**

```python
from kanban_e2e_hook import E2ECompletionGate

gate = E2ECompletionGate(
    base_url="http://192.168.1.50:8766",
    workspace_path=os.environ.get("HERMES_KANBAN_WORKSPACE", "."),
    skip_ui=True,  # Skip Playwright by default (fast, no deps)
    verbose=True,
)
result = gate.run()

if result.passed:
    kanban_complete(
        summary=result.summary_text(),
        metadata=result.metadata_dict(),
        artifacts=[result.report_path],
    )
else:
    kanban_comment(task_id=os.environ["HERMES_KANBAN_TASK"], body=result.failure_comment())
    kanban_block(reason=result.block_reason())
```

**Gate options:**

| Flag | Effect |
|------|--------|
| `--skip-ui` | Skip Playwright UI checks (~30s faster, no browser needed) |
| `--skip-api` | Skip API endpoint verification |
| `--skip-empty-state` | Skip empty-state messaging validation |
| `--seed` | Inject test data before verification |
| `--clean` | Clean test data after verification |

**Exit codes:** 0 = all checks passed (safe to kanban_complete), 1 = failures (must kanban_block).

**Block behavior:** Gate returns `passed=False` when:
- e2e_reporter exits non-zero (has FAIL-level issues)
- e2e_reporter crashes or is missing
- The target dashboard is unreachable

---

## Running Tests

### Quick verification (no Playwright, ~20s)

```bash
cd ~/opnsense-anomaly-agent
python3 e2e_reporter.py --base http://192.168.1.50:8766 --skip-ui
```

### Full verification (with Playwright, ~50s)

```bash
python3 e2e_reporter.py --base http://192.168.1.50:8766 --verbose
```

### With test data seeding

```bash
python3 e2e_reporter.py --base http://192.168.1.50:8766 --skip-ui --seed --clean
```

### Individual modules

```bash
python3 pipeline_verification.py --base http://192.168.1.50:8766
python3 api_verification.py --base http://192.168.1.50:8766
python3 empty_state_verification.py --base http://192.168.1.50:8766
python3 ui_verification.py --base http://192.168.1.50:8766
```

### Unit tests

```bash
cd ~/opnsense-anomaly-agent
python3 -m pytest tests/ -v
```

### Kanban gate (standalone)

```bash
python3 kanban_e2e_hook.py --base http://192.168.1.50:8766 --skip-ui --verbose
```

---

## Result Interpretation

### PASS
All checks green. Pipeline is healthy, data flows correctly, UI renders without errors. Safe to deploy/complete.

### WARN
Non-critical issues. Examples:
- Database status "warning" (degraded but functional)
- Empty endpoints with no contextual message (acceptable for data-driven tabs)
- Stats older than 5 minutes (agent may be processing slowly)
- Optional parser fields not populated

### FAIL
Blocking issues. Examples:
- API endpoint returning non-200 status
- Required fields missing from events
- Tab crashed with error boundary visible
- Schema version behind target
- Invalid timestamps in event data

### SKIP
Module intentionally skipped (e.g., `--skip-ui`) or Playwright not installed.

---

## Troubleshooting

### "Playwright not installed — UI verification skipped"
```bash
pip install playwright
playwright install chromium
```

### "Health endpoint returned 0" / connection refused
```bash
# Check container is running
docker ps | grep anomaly-agent

# Check port binding
docker port anomaly-agent

# Check if nginx proxy is running
curl http://localhost:8766/api/health
```

### "Database status: unhealthy"
```bash
# Check DB container
docker ps | grep postgres
docker logs anomaly-agent-db 2>&1 | tail -20

# Check connection
docker exec anomaly-agent-db psql -U anomaly_agent -c "SELECT 1"
```

### "Schema version behind target"
```bash
# Run pending migrations
docker exec anomaly-agent python3 schema_migrations.py

# Or restart container to auto-migrate
docker restart anomaly-agent
```

### Tabs showing "No data yet" with WARN
This is expected behavior. Tabs that depend on real syslog events (ZenArmor, IDS, Nginx) show NO_DATA or NOT_CONFIGURED until:
- ZenArmor: ZenArmor syslog entries arrive in the pipeline
- IDS: Suricata/Snort entries arrive
- Nginx: NGINX_STUB_STATUS_URL configured in .env
- OPNsense: OPNSENSE_API_URL and credentials configured

### Test data seeder fails
```bash
# Check DB connectivity
docker exec anomaly-agent python3 -c "from test_data_seeder import TestSeeder; TestSeeder().cleanup()"

# Check DB env vars match
grep DB_ .env
```

### Pipeline verification stage fails
```bash
# Run specific stage with verbose output
python3 pipeline_verification.py --stage <stage_name> --verbose --base http://192.168.1.50:8766

# Common stages: source, parser, agent, database, anomaly, baseline, api, ui_data
```

### "Tab Crashed" error in UI verification
```bash
# Check browser console for JS errors
python3 ui_verification.py --base http://192.168.1.50:8766 --screenshot-on fail --verbose

# Check dashboard logs
docker logs anomaly-agent 2>&1 | grep -i "error\|exception" | tail -20
```

---

## Current State of All 19 Tabs

| # | Tab | API Endpoint | Data Source | Status |
|---|-----|-------------|-------------|--------|
| 1 | Overview | /api/stats, /api/events | Syslog pipeline | Populated with live data |
| 2 | Heatmap | /api/heatmap | Parsed events | Canvas chart, populates with event data |
| 3 | Flow Map | /api/ip-flow, /api/traffic-flow | Parsed events | SVG force graph |
| 4 | IP Flow | /api/ip-flow | Parsed events | Node-link visualization |
| 5 | Geography | /api/geo | IP + geo lookup | Country distribution map |
| 6 | Alerts | /api/alerts | Anomaly detector | Table of threat alerts |
| 7 | Mutes | /api/mutes | User-managed | May be legitimately empty |
| 8 | ZenArmor | /api/zenarmor | ZenArmor syslog | DNS threat classification |
| 9 | IDS | /api/ids | IDS syslog | Signature match table |
| 10 | OPNsense | /api/opnsense | OPNsense API (port 6666) | System status: interfaces, gateways |
| 11 | Services | /api/services | Auto-discovered | Port detection from events |
| 12 | Nginx | /api/nginx | NGINX_STUB_STATUS_URL | Request stats, requires config |
| 13 | Network | /api/ip-flow-clusters | Parsed events | Clustered topology SVG |
| 14 | WAN Flap | /api/wan-flap | Interface syslog | Flap detection history |
| 15 | Firewall Rules | /api/rules | OPNsense API | Rules table |
| 16 | Rules ML | /api/rules-classified | ML classifier | Classified rules with confidence |
| 17 | Query Logs | /api/events | Events table | Searchable log viewer |
| 18 | Syslogs | /api/system_logs | System syslog | Raw system log entries |
| 19 | Settings | /api/health | Always available | Configuration controls |

### Known data pipeline issues

- **Nginx tab**: Requires `NGINX_STUB_STATUS_URL` in .env. Shows NOT_CONFIGURED until set up.
- **OPNsense tab**: Requires `OPNSENSE_API_URL` + credentials. Shows NOT_CONFIGURED until configured.
- **ZenArmor/IDS tabs**: Depend on corresponding syslog entries arriving in the pipeline. Shows NO_DATA until first events.
- **Mutes tab**: Empty is a valid configured state (no active mutes).
- **Legacy firewall rules**: Appear in syslog as RUID hashes but are NOT exposed by the API — expected and documented behavior.
- **Template sensors**: Depend on source sensor by name. If source unavailable, template shows "unknown". Trace upstream to source before modifying config.

### Database schema changes (V22)

**Tables deprecated (renamed to \*_deprecated):**

| Original table | Deprecated name | Superseded by |
|---------------|----------------|---------------|
| `nginx_events` | `nginx_events_deprecated` | `normalized_events` (source='nginx') |
| `unifi_events` | `unifi_events_deprecated` | `normalized_events` (source='unifi') |
| `unifi_devices` | `unifi_devices_deprecated` | Not backfilled (registry, different schema) |
| `unifi_clients` | `unifi_clients_deprecated` | Not backfilled (registry, different schema) |

**NOT deprecated:** The `events` table remains active — many `server.py` endpoints still query it directly. A follow-up migration will handle `events` deprecation.

**Why:** V21 (`normalized_events`) unified all event sources into a single hypertable with `source` discriminator + `payload_context` JSONB for source-specific fields. After the V21 backfill, the nginx/unifi tables are redundant. They were renamed (not dropped) as a safety net.

**Action required before dropping:** Verify `normalized_events` has sufficient data:
```sql
SELECT source, count(*) FROM normalized_events GROUP BY source;
```
Once verified, drop deprecated tables with:
```sql
DROP TABLE IF EXISTS nginx_events_deprecated;
DROP TABLE IF EXISTS unifi_events_deprecated;
DROP TABLE IF EXISTS unifi_devices_deprecated;
DROP TABLE IF EXISTS unifi_clients_deprecated;
```

**Code changes:** `server.py` (query_nginx_top_paths, query_nginx_timeline) and `dashboard_api.py` (_get_stats) now query `normalized_events` instead of legacy tables.

---

## E2E Enforcement Rules

### Deployment Gate (Automated — `deploy.sh`)

`deploy.sh` now runs a mandatory E2E verification gate **after** production health checks pass but **before** marking the deployment complete. This is Step 9 in the deploy flow.

**What runs (inside the container, against localhost:8766):**

| # | Script | Purpose | Duration |
|---|--------|---------|----------|
| 1 | `api_verification.py` | All API endpoints (26+ endpoints, ~210 checks) | ~15s |
| 2 | `empty_state_verification.py` | Per-tab empty-state messaging (26 tabs) | ~10s |
| 3 | `pipeline_verification.py` | 8-stage source-to-UI trace | ~20s |

**Exit behavior:**

- **All pass** → Deploy continues to cleanup + success message.
- **Any FAIL** → Deploy **ABORTS**: failed container stopped, previous version automatically restored via rollback, script exits 1.
- **Script crash** → Treated as FAIL (same rollback behavior).

**No skip flags.** There are no `--skip-e2e` or `--force` flags in deploy.sh. The gate is mandatory.

**Success output includes E2E confirmation:**

```
[+] Deploy successful! Version: abc1234
[+] Image: opnsense-anomaly-agent:abc1234
[+] Previous: opnsense-anomaly-agent:def5678 (rollback available)
[+] E2E verification: PASSED
```

### Kanban Completion Gate (Worker-enforced)

Every kanban worker that modifies the anomaly agent MUST run E2E verification before calling `kanban_complete()`. See `KANBAN_E2E_GATE.md` and `kanban_e2e_hook.py`.

```python
from kanban_e2e_hook import E2ECompletionGate

gate = E2ECompletionGate(
    base_url="http://192.168.1.50:8766",
    workspace_path=os.environ.get("HERMES_KANBAN_WORKSPACE", "."),
    skip_ui=True,
    verbose=True,
)
result = gate.run()

if result.passed:
    kanban_complete(summary=..., metadata=..., artifacts=[result.report_path])
else:
    kanban_comment(task_id=..., body=result.failure_comment())
    kanban_block(reason=result.block_reason())
```

### Enforcement Rules

1. **Never skip E2E verification.** Not for "small changes," not for hotfixes, not for config-only changes. A one-line YAML fix can break an API endpoint.
2. **Block on FAIL.** If any E2E check returns FAIL, the task is blocked with `kanban_block()`. Do not complete with a note "E2E failed but I think it's fine."
3. **Run after deploy, before declare-done.** E2E verification happens after the code is deployed and the health check passes, but before the deploy script reports success.
4. **Worker-created E2E modules crash on live APIs.** Always test new E2E modules against the live system before committing — unit tests are necessary but insufficient.
5. **Rollback is automatic.** Both `deploy.sh` and `kanban_e2e_hook.py` handle rollback. If E2E fails, the previous version is restored automatically.

---

## File Reference

| File | Purpose |
|------|---------|
| `test_data_seeder.py` | Marker-based test data injection & cleanup |
| `pipeline_verification.py` | 8-stage source-to-UI trace |
| `api_verification.py` | API endpoint verification (26+ endpoints) |
| `empty_state_verification.py` | Empty-state messaging validation (26 tabs) |
| `ui_verification.py` | Playwright UI rendering (19 tabs) |
| `e2e_reporter.py` | Orchestrator + consolidated JSON report |
| `kanban_e2e_hook.py` | Kanban completion gate |
| `KANBAN_E2E_GATE.md` | Gate usage guide |
| `tests/test_seeder.py` | Unit tests for test_data_seeder |
| `tests/test_pipeline_verification.py` | Unit tests for pipeline_verification |
| `tests/test_empty_state_verification.py` | Unit tests for empty_state_verification |
| `tests/README.md` | Test suite architecture documentation |

### Behavioral Engine Modules (unified)

| File | Purpose | Status |
|------|---------|--------|
| `unified_behavioral_engine.py` | Unified engine: IP behavioral profiling, threat scoring, baselines, statistical models | **ACTIVE** |
| `ip_behavior_model.py` | Per-IP EMA baselines, deviation signals | **DEPRECATED** → use `unified_behavioral_engine.py` |
| `threat_engine.py` | Multi-source threat scoring, adaptive weights | **DEPRECATED** → use `unified_behavioral_engine.py` |
| `baseline_engine.py` | Rule-level → IP-level traffic baselines | **DEPRECATED** → use `unified_behavioral_engine.py` |
| `statistical_model.py` | Global rolling statistics, z-score anomaly detection | **DEPRECATED** → use `unified_behavioral_engine.py` |

> **Note:** The 4 deprecated modules are retained until 2026-07-14 as a safety net. They emit `DeprecationWarning` on import and contain migration comments. After the retention window they will be removed.
