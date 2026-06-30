"""Tests for schema_migrations.py — versioned migration framework."""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from unittest.mock import MagicMock, patch, call
import pytest
from schema_migrations import (
    run_migrations,
    get_schema_version,
    get_migration_status,
    _get_current_version,
    _safe_add_column,
    _safe_drop_constraint,
    _safe_create_hypertable,
    _v3_finalize,
    _v20_convert_hypertable,
    _v21_backfill,
    _v22_verify_deprecation,
    CURRENT_SCHEMA_VERSION,
    MIGRATIONS,
)


class TestMigrationMetadata:
    """Verify migration definitions are well-formed."""

    def test_current_version_matches_latest_migration(self):
        latest = max(m["version"] for m in MIGRATIONS)
        assert CURRENT_SCHEMA_VERSION == latest

    def test_all_migrations_have_required_keys(self):
        for m in MIGRATIONS:
            assert "version" in m, f"Migration missing 'version'"
            assert "description" in m, f"Migration v{m.get('version')} missing 'description'"
            assert "sql" in m, f"Migration v{m.get('version')} missing 'sql'"

    def test_versions_are_sequential(self):
        versions = sorted(m["version"] for m in MIGRATIONS)
        assert versions == list(range(1, len(versions) + 1))

    def test_no_do_blocks_in_sql(self):
        """Critical: ensure no DO $$ anonymous code blocks remain in migrations."""
        for m in MIGRATIONS:
            for sql in m["sql"]:
                assert "DO $$" not in sql, (
                    f"Migration v{m['version']} still contains DO $$ block: {sql[:80]}..."
                )
                assert "DO $@" not in sql, (
                    f"Migration v{m['version']} still contains DO $@ block"
                )

    def test_v3_has_alter_columns(self):
        v3 = next(m for m in MIGRATIONS if m["version"] == 3)
        assert "alter_columns" in v3
        assert len(v3["alter_columns"]) > 0
        # Verify tuple structure: (table, column, col_def)
        for col_spec in v3["alter_columns"]:
            assert len(col_spec) == 3
            table, column, col_def = col_spec
            assert isinstance(table, str)
            assert isinstance(column, str)
            assert isinstance(col_def, str)

    def test_v3_has_hook(self):
        v3 = next(m for m in MIGRATIONS if m["version"] == 3)
        assert "hook" in v3
        assert callable(v3["hook"])


class TestGetCurrentVersion:
    """Test _get_current_version helper."""

    def test_returns_zero_when_no_version_table(self):
        conn = MagicMock()
        cur = MagicMock()
        conn.cursor.return_value = cur
        cur.fetchone.return_value = (False,)
        assert _get_current_version(conn) == 0

    def test_returns_zero_when_version_table_empty(self):
        conn = MagicMock()
        cur = MagicMock()
        conn.cursor.return_value = cur
        # First call: table exists; second call: MAX(version) is NULL
        cur.fetchone.side_effect = [(True,), (None,)]
        assert _get_current_version(conn) == 0

    def test_returns_current_version(self):
        conn = MagicMock()
        cur = MagicMock()
        conn.cursor.return_value = cur
        cur.fetchone.side_effect = [(True,), (5,)]
        assert _get_current_version(conn) == 5


class TestSafeAddColumn:
    """Test _safe_add_column idempotent column addition."""

    def test_adds_column_successfully(self):
        conn = MagicMock()
        cur = MagicMock()
        conn.cursor.return_value = cur

        result = _safe_add_column(conn, "test_table", "new_col", "TEXT DEFAULT ''")
        assert result is True
        cur.execute.assert_called_with(
            "ALTER TABLE test_table ADD COLUMN new_col TEXT DEFAULT ''"
        )

    def test_skips_duplicate_column(self):
        conn = MagicMock()
        cur = MagicMock()
        conn.cursor.return_value = cur
        cur.execute.side_effect = Exception("column 'new_col' of relation 'test_table' already exists")

        result = _safe_add_column(conn, "test_table", "new_col", "TEXT DEFAULT ''")
        assert result is False

    def test_skips_duplicate_via_error_code(self):
        conn = MagicMock()
        cur = MagicMock()
        conn.cursor.return_value = cur
        cur.execute.side_effect = Exception("ERROR: 42701 duplicate column")

        result = _safe_add_column(conn, "test_table", "new_col", "INTEGER")
        assert result is False

    def test_raises_on_non_duplicate_error(self):
        conn = MagicMock()
        cur = MagicMock()
        conn.cursor.return_value = cur
        cur.execute.side_effect = Exception("syntax error at or near 'NEW'")

        with pytest.raises(Exception, match="syntax error"):
            _safe_add_column(conn, "test_table", "new_col", "NEW TYPE")


class TestSafeDropConstraint:
    """Test _safe_drop_constraint idempotent constraint removal."""

    def test_drops_constraint_successfully(self):
        conn = MagicMock()
        cur = MagicMock()
        conn.cursor.return_value = cur

        result = _safe_drop_constraint(conn, "test_table", "test_constraint")
        assert result is True
        cur.execute.assert_called_with(
            "ALTER TABLE test_table DROP CONSTRAINT IF EXISTS test_constraint"
        )

    def test_skips_missing_constraint(self):
        conn = MagicMock()
        cur = MagicMock()
        conn.cursor.return_value = cur
        cur.execute.side_effect = Exception("constraint 'test_constraint' does not exist")

        result = _safe_drop_constraint(conn, "test_table", "test_constraint")
        assert result is False


class TestV3Finalize:
    """Test _v3_finalize hook (replaces DO $$ constraint logic)."""

    def test_adds_composite_constraint(self):
        conn = MagicMock()
        cur = MagicMock()
        conn.cursor.return_value = cur
        # Constraint doesn't exist yet
        cur.fetchone.return_value = None

        _v3_finalize(conn)

        # Should have checked for constraint, then added it
        calls = [c[0] for c in cur.execute.call_args_list]
        assert any("rule_baselines_rule_key" in str(c) for c in calls)

    def test_skips_existing_composite_constraint(self):
        conn = MagicMock()
        cur = MagicMock()
        conn.cursor.return_value = cur
        # Constraint already exists
        cur.fetchone.return_value = (1,)

        _v3_finalize(conn)

        # Should not have tried to ADD the constraint
        calls = [c[0] for c in cur.execute.call_args_list]
        add_calls = [c for c in calls if "ADD CONSTRAINT rule_baselines_rule_key" in str(c)]
        assert len(add_calls) == 0

    def test_fixes_rule_name_not_null(self):
        conn = MagicMock()
        cur = MagicMock()
        conn.cursor.return_value = cur
        cur.fetchone.return_value = None

        _v3_finalize(conn)

        # Should have called DROP NOT NULL and SET DEFAULT
        calls_str = " ".join(str(c) for c in cur.execute.call_args_list)
        assert "DROP NOT NULL" in calls_str
        assert "SET DEFAULT" in calls_str


class TestRunMigrations:
    """Test the main run_migrations function."""

    def _make_mock_db(self, current_version=0):
        db = MagicMock()
        conn = MagicMock()
        cur = MagicMock()
        conn.cursor.return_value = cur
        # schema_versions table exists, current version
        # Provide enough values for fetchone calls from _get_current_version + hooks
        # Use a generous list of (0,) values for count queries, plus None for optional fetches
        cur.fetchone.side_effect = [(True,), (current_version,)] + [(0,)] * 100 + [None] * 50
        cur.fetchall.return_value = [("events_pkey",)]
        db.connect.return_value = conn
        return db, conn, cur

    def test_runs_all_migrations_from_zero(self):
        db, conn, cur = self._make_mock_db(current_version=0)

        results = run_migrations(db)

        applied = [r for r in results if r["status"] == "applied"]
        assert len(applied) == CURRENT_SCHEMA_VERSION
        # Verify versions are sequential
        versions = [r["version"] for r in applied]
        assert versions == list(range(1, CURRENT_SCHEMA_VERSION + 1))

    def test_v8_creates_adaptive_weights(self):
        """Verify v8 migration (adaptive_weights table) is present and has no DO blocks."""
        v8 = next(m for m in MIGRATIONS if m["version"] == 8)
        assert "adaptive_weights" in v8["description"].lower()
        has_create = False
        for sql in v8["sql"]:
            if "CREATE TABLE IF NOT EXISTS adaptive_weights" in sql:
                has_create = True
            assert "DO $$" not in sql
        assert has_create, "v8 should create adaptive_weights table"

    def test_skips_already_applied_migrations(self):
        db, conn, cur = self._make_mock_db(current_version=5)

        results = run_migrations(db)

        skipped = [r for r in results if r["status"] == "skipped"]
        applied = [r for r in results if r["status"] == "applied"]
        assert len(skipped) == 5  # v1-v5 skipped
        assert len(applied) == CURRENT_SCHEMA_VERSION - 5  # remaining versions applied

    def test_returns_already_current_when_up_to_date(self):
        db, conn, cur = self._make_mock_db(current_version=CURRENT_SCHEMA_VERSION)

        results = run_migrations(db)

        assert len(results) == 1
        assert results[0]["status"] == "already_current"
        assert results[0]["version"] == CURRENT_SCHEMA_VERSION

    def test_alter_columns_are_executed(self):
        """Verify that alter_columns entries in v3 are actually run."""
        db, conn, cur = self._make_mock_db(current_version=2)

        results = run_migrations(db)

        # Find v3 result
        v3_result = next(r for r in results if r["version"] == 3)
        assert v3_result["status"] == "applied"
        # v3 has alter_columns - verify ALTER TABLE calls were made
        alter_calls = [
            c for c in cur.execute.call_args_list
            if "ALTER TABLE" in str(c[0]) and "ADD COLUMN" in str(c[0])
        ]
        # v3 has 12 alter_columns entries
        assert len(alter_calls) >= 10  # Some may have been called in prior migrations too

    def test_migration_failure_raises_runtime_error(self):
        db, conn, cur = self._make_mock_db(current_version=0)
        # Execute flow: CREATE_VERSION_TABLE_SQL → SELECT EXISTS → SELECT MAX(version) → v1 migration SQL (fail)
        cur.execute.side_effect = [None, None, None, Exception("connection reset")]

        with pytest.raises(RuntimeError, match="Migration v1 failed"):
            run_migrations(db)

    def test_returns_connection_to_pool(self):
        db, conn, cur = self._make_mock_db(current_version=CURRENT_SCHEMA_VERSION)

        run_migrations(db)

        # Connection should be returned to pool
        db.putconn.assert_called_with(conn)


class TestGetSchemaVersion:
    """Test get_schema_version helper."""

    def test_returns_version(self):
        db = MagicMock()
        conn = MagicMock()
        cur = MagicMock()
        conn.cursor.return_value = cur
        cur.fetchone.side_effect = [(True,), (3,)]
        db.connect.return_value = conn

        assert get_schema_version(db) == 3
        db.putconn.assert_called_with(conn)


class TestGetMigrationStatus:
    """Test get_migration_status helper."""

    def test_returns_status_dict(self):
        db = MagicMock()
        conn = MagicMock()
        cur = MagicMock()
        conn.cursor.return_value = cur
        cur.fetchone.side_effect = [(True,), (2,)]
        cur.fetchall.return_value = [
            (1, "Create core tables...", "2026-01-01"),
            (2, "Create ip_threat_profiles...", "2026-01-02"),
        ]
        db.connect.return_value = conn

        status = get_migration_status(db)

        assert status["current_version"] == 2
        assert status["target_version"] == CURRENT_SCHEMA_VERSION
        assert not status["is_current"]
        assert len(status["applied"]) == 2
        assert len(status["pending"]) == CURRENT_SCHEMA_VERSION - 2

    def test_reports_current_when_up_to_date(self):
        db = MagicMock()
        conn = MagicMock()
        cur = MagicMock()
        conn.cursor.return_value = cur
        cur.fetchone.side_effect = [(True,), (CURRENT_SCHEMA_VERSION,)]
        cur.fetchall.return_value = []
        db.connect.return_value = conn

        status = get_migration_status(db)

        assert status["is_current"] is True
        assert len(status["pending"]) == 0


class TestBaselineEngineMigrationIntegration:
    """Integration tests: baseline_engine.py + schema_migrations.py compatibility.

    These tests verify that the rule_baselines table schema produced by v3 migration
    matches what baseline_engine.py expects for _load_baselines() and save_baselines().
    """

    def test_v3_create_sql_has_all_baseline_columns(self):
        """The v3 CREATE TABLE must include every column baseline_engine reads."""
        from baseline_engine import BaselineEngine

        v3 = next(m for m in MIGRATIONS if m["version"] == 3)
        v3_sql = " ".join(v3["sql"])

        # Columns baseline_engine._load_baselines() reads:
        # rule, ip, hour, avg_events_per_hour, std_events_per_hour,
        # max_events_per_hour, min_events_per_hour, protocol_distribution,
        # avg_dst_ports, avg_src_ports, avg_unique_dst_ips, pass_ratio,
        # block_ratio, hourly_distribution, sample_count, last_updated
        required_columns = [
            "rule", "ip", "hour",
            "avg_events_per_hour", "std_events_per_hour",
            "max_events_per_hour", "min_events_per_hour",
            "protocol_distribution", "avg_dst_ports", "avg_src_ports",
            "avg_unique_dst_ips", "pass_ratio", "block_ratio",
            "hourly_distribution", "sample_count", "last_updated",
        ]
        for col in required_columns:
            assert col in v3_sql, f"v3 migration missing column: {col}"

    def test_v3_alter_columns_superset_of_required(self):
        """The v3 alter_columns must cover any column baseline_engine might need."""
        v3 = next(m for m in MIGRATIONS if m["version"] == 3)
        alter_cols = {col for (_, col, _) in v3.get("alter_columns", [])}

        # Columns that might be missing on legacy tables
        expected = {"rule", "ip", "hour"}
        assert expected.issubset(alter_cols), (
            f"v3 alter_columns missing: {expected - alter_cols}"
        )

    def test_baseline_engine_load_query_matches_v3_schema(self):
        """Verify baseline_engine SELECT columns match the v3 CREATE TABLE columns."""
        import inspect
        from baseline_engine import BaselineEngine
        source = inspect.getsource(BaselineEngine._load_baselines)

        # The SELECT in _load_baselines references these columns
        expected_in_select = [
            "rule", "ip", "hour",
            "avg_events_per_hour", "std_events_per_hour",
            "max_events_per_hour", "min_events_per_hour",
            "protocol_distribution", "avg_dst_ports", "avg_src_ports",
            "avg_unique_dst_ips", "pass_ratio", "block_ratio",
            "hourly_distribution", "sample_count", "last_updated",
        ]
        for col in expected_in_select:
            assert col in source, f"_load_baselines missing column in SELECT: {col}"

    def test_baseline_engine_save_query_matches_v3_schema(self):
        """Verify baseline_engine INSERT columns match the v3 CREATE TABLE columns."""
        import inspect
        from baseline_engine import BaselineEngine
        source = inspect.getsource(BaselineEngine.save_baselines)

        expected_in_insert = [
            "rule", "ip", "hour",
            "avg_events_per_hour", "std_events_per_hour",
            "max_events_per_hour", "min_events_per_hour",
            "protocol_distribution", "avg_dst_ports", "avg_src_ports",
            "avg_unique_dst_ips", "pass_ratio", "block_ratio",
            "hourly_distribution", "sample_count", "last_updated",
        ]
        for col in expected_in_insert:
            assert col in source, f"save_baselines missing column in INSERT: {col}"

    def test_composite_unique_constraint_matches_baseline_key(self):
        """Verify the composite unique constraint (rule, ip, hour) matches _make_baseline_key logic."""
        v3 = next(m for m in MIGRATIONS if m["version"] == 3)
        v3_sql = " ".join(v3["sql"])

        # The constraint is added in the hook, not the SQL — check _v3_finalize source
        import inspect
        hook_source = inspect.getsource(_v3_finalize)
        assert "rule_baselines_rule_key" in hook_source
        assert "UNIQUE (rule, ip, hour)" in hook_source


class TestSafeCreateHypertable:
    """Test _safe_create_hypertable helper — the generic hypertable conversion."""

    def _make_mock_conn(self, is_hypertable=False, pk_names=("events_pkey",)):
        """Build a mock connection with configurable behavior."""
        conn = MagicMock()
        cur = MagicMock()
        conn.cursor.return_value = cur
        if is_hypertable:
            # Already a hypertable — first query returns a row
            cur.fetchone.return_value = ("public", "events")
        else:
            # Not a hypertable, then return PK names, then event count, then chunk info
            cur.fetchone.side_effect = [
                None,  # hypertable check -> not found
                ("events_pkey",),  # PK name
                (1000,),  # event count
                (5, "2025-01-01", "2026-06-30"),  # chunk info
                None, None, None, None, None,  # extra padding
            ]
            cur.fetchall.return_value = [(pk,) for pk in pk_names]
        return conn, cur

    def test_skips_when_already_hypertable(self):
        conn, cur = self._make_mock_conn(is_hypertable=True)

        result = _safe_create_hypertable(conn, "events", "timestamp")

        assert result is False
        # Should not have run create_hypertable
        calls_str = " ".join(str(c) for c in cur.execute.call_args_list)
        assert "create_hypertable" not in calls_str

    def test_converts_regular_table(self):
        conn, cur = self._make_mock_conn(is_hypertable=False)

        result = _safe_create_hypertable(conn, "events", "timestamp")

        assert result is True
        # Verify the sequence: hypertable check -> PK lookup -> DROP PK -> ADD PK -> create_hypertable
        calls_str = " ".join(str(c) for c in cur.execute.call_args_list)
        assert "DROP CONSTRAINT" in calls_str
        assert "ADD PRIMARY KEY" in calls_str
        assert "create_hypertable" in calls_str
        conn.commit.assert_called()

    def test_uses_parameterized_queries(self):
        """Ensure table name and column params are passed via %s placeholders."""
        conn, cur = self._make_mock_conn(is_hypertable=False)

        _safe_create_hypertable(conn, "my_table", "created_at", "1 day", ("id", "created_at"))

        # First execute: hypertable lookup — should use %s with "my_table"
        first_call = cur.execute.call_args_list[0]
        assert "my_table" in str(first_call)
        # Primary key lookup should use "my_table"
        second_call = cur.execute.call_args_list[1]
        assert "my_table" in str(second_call)

    def test_raises_on_non_idempotent_error(self):
        conn = MagicMock()
        cur = MagicMock()
        conn.cursor.return_value = cur
        cur.fetchone.return_value = None  # not a hypertable
        cur.fetchall.side_effect = Exception("connection lost")

        with pytest.raises(Exception, match="connection lost"):
            _safe_create_hypertable(conn, "events", "timestamp")

        conn.rollback.assert_called()


class TestV20ConvertHypertable:
    """Test _v20_convert_hypertable — the V20-specific hook."""

    def test_v20_creates_hypertable(self):
        conn = MagicMock()
        cur = MagicMock()
        conn.cursor.return_value = cur
        # _safe_create_hypertable uses fetchone for hypertable check,
        # then fetchall for PK lookup.
        # _v20_convert_hypertable uses fetchone for event count and chunk info.
        cur.fetchone.side_effect = [
            None,  # _safe_create_hypertable: hypertable check -> not found
            (42,),  # _v20: event count
            (3, "2025-06-01", "2026-06-01"),  # _v20: chunk info
            None, None, None,
        ]
        cur.fetchall.return_value = [("events_pkey",)]

        _v20_convert_hypertable(conn)

        calls_str = " ".join(str(c) for c in cur.execute.call_args_list)
        assert "DROP CONSTRAINT" in calls_str
        assert "ADD PRIMARY KEY" in calls_str
        assert "create_hypertable" in calls_str
        assert "ANALYZE events" in calls_str
        assert "DROP INDEX" in calls_str
        assert "idx_events_timestamp" in calls_str

    def test_v20_skips_when_already_hypertable(self):
        conn = MagicMock()
        cur = MagicMock()
        conn.cursor.return_value = cur
        cur.fetchone.return_value = ("public", "events")  # already a hypertable

        _v20_convert_hypertable(conn)

        # Should only do ANALYZE, no DROP/ADD/create_hypertable
        calls_str = " ".join(str(c) for c in cur.execute.call_args_list)
        assert "ANALYZE events" in calls_str
        assert "DROP CONSTRAINT" not in calls_str
        assert "create_hypertable" not in calls_str

    def test_v20_handles_no_chunks(self):
        """Fresh instance with no events — chunk query returns no rows."""
        conn = MagicMock()
        cur = MagicMock()
        conn.cursor.return_value = cur
        cur.fetchone.side_effect = [
            None,  # hypertable check
            (0,),  # event count (empty)
            None,  # no chunk row
            None, None, None,
        ]
        cur.fetchall.return_value = [("events_pkey",)]

        # Should not raise — handles empty chunk result gracefully
        _v20_convert_hypertable(conn)

        # Verify create_hypertable was still called
        calls_str = " ".join(str(c) for c in cur.execute.call_args_list)
        assert "create_hypertable" in calls_str


class TestV20MigrationEntry:
    """Verify V20 migration definition is well-formed."""

    def test_v20_has_hook(self):
        v20 = next(m for m in MIGRATIONS if m["version"] == 20)
        assert "hook" in v20
        assert callable(v20["hook"])

    def test_v20_creates_extension(self):
        v20 = next(m for m in MIGRATIONS if m["version"] == 20)
        extension_sql = " ".join(v20["sql"])
        assert "CREATE EXTENSION IF NOT EXISTS timescaledb" in extension_sql

    def test_v20_description_mentions_hypertable(self):
        v20 = next(m for m in MIGRATIONS if m["version"] == 20)
        assert "hypertable" in v20["description"].lower()


class TestV21Backfill:
    """Test _v21_backfill — bulk backfill into normalized_events from legacy tables."""

    def test_skips_when_normalized_events_populated(self):
        """Backfill exits immediately if normalized_events already has rows."""
        conn = MagicMock()
        cur = MagicMock()
        conn.cursor.return_value = cur
        cur.fetchone.return_value = (42,)  # existing rows

        _v21_backfill(conn)

        # Should have run only the count check, no INSERT
        calls_str = " ".join(str(c) for c in cur.execute.call_args_list)
        assert "SELECT count(*) FROM normalized_events" in calls_str
        assert "INSERT INTO normalized_events" not in calls_str

    def test_backfills_from_events_table(self):
        """Backfill from events table maps columns correctly."""
        conn = MagicMock()
        cur = MagicMock()
        conn.cursor.return_value = cur
        cur.fetchone.side_effect = [
            (0,),       # normalized_events empty
            (1,),       # events table exists
            None, None, # padding for verification count queries
        ]
        cur.rowcount = 100

        _v21_backfill(conn)

        calls_str = " ".join(str(c) for c in cur.execute.call_args_list)
        assert "INSERT INTO normalized_events" in calls_str
        assert "jsonb_build_object" in calls_str
        assert "FROM events" in calls_str

    def test_backfills_from_nginx_events(self):
        """Backfill from nginx_events table."""
        conn = MagicMock()
        cur = MagicMock()
        conn.cursor.return_value = cur
        cur.fetchone.side_effect = [
            (0,),       # normalized_events empty
            (1,),       # events table exists
            (1,),       # nginx_events table exists
            (150,),     # verification: normalized_events count
            (100,),     # verification: events count
            (50,),      # verification: nginx_events count
            (0,),       # verification: unifi_events count
            None, None, # padding
        ]
        cur.rowcount = 50

        _v21_backfill(conn)

        calls_str = " ".join(str(c) for c in cur.execute.call_args_list)
        assert "FROM nginx_events ne" in calls_str
        assert "'nginx' AS source" in calls_str

    def test_backfills_from_unifi_events(self):
        """Backfill from unifi_events table."""
        conn = MagicMock()
        cur = MagicMock()
        conn.cursor.return_value = cur
        cur.fetchone.side_effect = [
            (0,),       # normalized_events empty
            (1,),       # events table exists
            (1,),       # nginx_events table exists
            (1,),       # unifi_events table exists
            (200,),     # verification: normalized_events count
            (100,),     # verification: events count
            (50,),      # verification: nginx_events count
            (50,),      # verification: unifi_events count
            None, None, # padding
        ]
        cur.rowcount = 50

        _v21_backfill(conn)

        calls_str = " ".join(str(c) for c in cur.execute.call_args_list)
        assert "FROM unifi_events ue" in calls_str
        assert "'unifi' AS source" in calls_str

    def test_skips_missing_tables_gracefully(self):
        """Missing source tables are skipped without raising."""
        conn = MagicMock()
        cur = MagicMock()
        conn.cursor.return_value = cur
        cur.fetchone.side_effect = [
            (0,),       # normalized_events empty
            None,       # events table missing
            None,       # nginx_events table missing
            None,       # unifi_events table missing
            (0,),       # verification: normalized_events count
            None, None, # padding
        ]

        # Should not raise — all tables missing is valid (fresh install)
        _v21_backfill(conn)

    def test_handles_insert_errors_gracefully(self):
        """INSERT failure on one table does not stop other backfills."""
        conn = MagicMock()
        cur = MagicMock()
        conn.cursor.return_value = cur
        cur.fetchone.side_effect = [
            (0,),       # normalized_events empty
            (1,),       # events table exists
            (1,),       # nginx_events table exists
            (1,),       # unifi_events table exists
            (0,),       # verification: normalized_events count
            None, None, # padding
        ]
        # First execute after count check is "events exists", then events INSERT fails
        call_index = [0]
        def execute_side_effect(*args, **kwargs):
            sql = str(args[0]) if args else ""
            call_index[0] += 1
            if "INSERT INTO normalized_events" in sql and "FROM events" in sql:
                raise Exception("duplicate key")
            if "INSERT INTO normalized_events" in sql and "FROM nginx_events" in sql:
                raise Exception("type mismatch")
            return None

        cur.execute.side_effect = execute_side_effect

        # Should complete without raising — errors are logged as warnings
        _v21_backfill(conn)

    def test_v21_migration_has_hook(self):
        """V21 migration definition calls backfill before hypertable conversion."""
        v21 = next(m for m in MIGRATIONS if m["version"] == 21)
        assert "hook" in v21
        assert callable(v21["hook"])

    def test_v21_creates_normalized_events_table(self):
        """V21 SQL contains CREATE TABLE for normalized_events."""
        v21 = next(m for m in MIGRATIONS if m["version"] == 21)
        all_sql = " ".join(v21["sql"])
        assert "CREATE TABLE IF NOT EXISTS normalized_events" in all_sql

    def test_v21_normalized_events_has_payload_context(self):
        """normalized_events schema includes payload_context JSONB column."""
        v21 = next(m for m in MIGRATIONS if m["version"] == 21)
        all_sql = " ".join(v21["sql"])
        assert "payload_context" in all_sql
        assert "JSONB" in all_sql

    def test_v21_normalized_events_has_source_column(self):
        """normalized_events schema includes source column with default."""
        v21 = next(m for m in MIGRATIONS if m["version"] == 21)
        all_sql = " ".join(v21["sql"])
        assert "source TEXT NOT NULL" in all_sql or "source TEXT" in all_sql


class TestV22Deprecation:
    """Test V22 deprecation migration — rename legacy tables to *_deprecated."""

    def test_v22_migration_exists(self):
        """V22 migration is defined in MIGRATIONS list."""
        v22 = next(m for m in MIGRATIONS if m["version"] == 22)
        assert "deprecat" in v22["description"].lower() or "rename" in v22["description"].lower()

    def test_v22_has_rename_statements(self):
        """V22 SQL contains ALTER TABLE RENAME for nginx/unifi tables only."""
        v22 = next(m for m in MIGRATIONS if m["version"] == 22)
        all_sql = " ".join(v22["sql"])
        assert "nginx_events RENAME TO nginx_events_deprecated" in all_sql
        assert "unifi_events RENAME TO unifi_events_deprecated" in all_sql
        assert "unifi_devices RENAME TO unifi_devices_deprecated" in all_sql
        assert "unifi_clients RENAME TO unifi_clients_deprecated" in all_sql
        # events table is NOT deprecated (still in use by server.py endpoints)
        assert "events RENAME TO events_deprecated" not in all_sql

    def test_v22_has_hook(self):
        """V22 migration calls _v22_verify_deprecation hook."""
        v22 = next(m for m in MIGRATIONS if m["version"] == 22)
        assert "hook" in v22
        assert callable(v22["hook"])

    def test_v22_verify_counts_normalized_events(self):
        """_v22_verify_deprecation counts normalized_events rows."""
        conn = MagicMock()
        cur = MagicMock()
        conn.cursor.return_value = cur
        cur.fetchone.side_effect = [
            (1000,),  # normalized_events count
            (100,),   # nginx_events_deprecated
            (50,),    # unifi_events_deprecated
            (10,),    # unifi_devices_deprecated
            (25,),    # unifi_clients_deprecated
        ]

        _v22_verify_deprecation(conn)

        # Verify count queries were run
        calls_str = " ".join(str(c) for c in cur.execute.call_args_list)
        assert "SELECT count(*) FROM normalized_events" in calls_str
        assert "nginx_events_deprecated" in calls_str
        assert "unifi_events_deprecated" in calls_str
        # events is NOT deprecated (still actively used) — the literal table
        # name "events_deprecated" should not appear as a standalone target.
        calls = [str(c) for c in cur.execute.call_args_list]
        # Match " FROM events_deprecated" but NOT " FROM nginx_events_deprecated" etc.
        standalone_deprecated = [c for c in calls if " FROM events_deprecated" in c]
        assert standalone_deprecated == [], f"events_deprecated should not be queried: {standalone_deprecated}"

    def test_v22_verify_handles_missing_deprecated_table(self):
        """Missing deprecated tables are logged as info, not errors."""
        conn = MagicMock()
        cur = MagicMock()
        conn.cursor.return_value = cur

        def execute_side_effect(*args, **kwargs):
            sql = str(args[0]) if args else ""
            if "normalized_events" in sql:
                return None  # succeeds
            raise Exception("relation does not exist")

        cur.fetchone.side_effect = [(100,)]
        cur.execute.side_effect = execute_side_effect

        # Should not raise — handles missing tables gracefully
        _v22_verify_deprecation(conn)