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
    _v3_finalize,
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
        cur.fetchone.side_effect = [(True,), (current_version,), None, None, None, None, None]
        cur.fetchall.return_value = []
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

    def test_skips_already_applied_migrations(self):
        db, conn, cur = self._make_mock_db(current_version=5)

        results = run_migrations(db)

        skipped = [r for r in results if r["status"] == "skipped"]
        applied = [r for r in results if r["status"] == "applied"]
        assert len(skipped) == 5  # v1-v5 skipped
        assert len(applied) == 2  # v6, v7 applied

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