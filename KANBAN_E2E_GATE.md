# Kanban E2E Completion Gate — Usage Guide

> Every kanban worker that modifies the OPNsense anomaly agent MUST run E2E verification before calling `kanban_complete()`. If E2E fails, the worker blocks the task with structured failure details.

## Why

The user demands automated E2E verification — not manual visual inspection. This gate runs the full test suite (pipeline health, API trace, empty state verification) against the deployed agent and gates task completion on failures.

## Pre-commit hook — how to wire into kanban_complete

The `kanban_e2e_hook.py` module provides `E2ECompletionGate`. A worker calls it like this:

```python
# At the end of the worker, BEFORE kanban_complete()
import sys
sys.path.insert(0, "/Users/timolow/opnsense-anomaly-agent")
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

## CLI usage (for humans)

```bash
# Quick gate check (API + empty state only)
python3 kanban_e2e_hook.py --base http://192.168.1.50:8766 --skip-ui

# Full gate including UI verification (requires Playwright)
python3 kanban_e2e_hook.py --base http://192.168.1.50:8766

# Write metadata JSON for scripting
python3 kanban_e2e_hook.py --base http://192.168.1.50:8766 --skip-ui --json-only
```

## Report format

`e2e-report.json` contains:
- `report`: Timestamp, base URL, overall PASS/FAIL status
- `pipeline_health`: Health of syslog, DB, Discord, Redis subsystems
- `api_verification`: Per-endpoint results (52 endpoints, ~210 checks)
- `empty_state_verification`: Per-tab empty-state messaging validation (20 tabs)
- `ui_verification`: Playwright-based UI rendering checks (19 tabs, 97 checks)
- `per_tab_status`: Consolidated PASS/FAIL per dashboard tab
- `issues`: All WARN/FAIL items across all modules
- `summary`: Totals (passed, warnings, failures, skipped)

## Gate options

| Flag | Effect |
|------|--------|
| `--skip-ui` | Skip Playwright UI checks (~30s faster, no browser needed) |
| `--skip-api` | Skip API endpoint verification |
| `--skip-empty-state` | Skip empty-state messaging validation |
| `--seed` | Inject test data before verification |
| `--clean` | Clean test data after verification |

## Exit codes

- `0` — All checks passed. Safe to `kanban_complete()`.
- `1` — One or more checks failed. Must `kanban_block()`.

## What the gate blocks on

The gate returns `passed=False` when:
- `e2e_reporter` exits non-zero (has FAIL-level issues)
- `e2e_reporter` crashes or is missing
- The target dashboard is unreachable

## Memory rule

Workers: do NOT skip the gate even for "small changes". A one-line config fix can break an API endpoint. The gate runs in ~20s and catches regressions before they reach the user.
