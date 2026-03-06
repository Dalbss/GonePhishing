"""
GonePhishing - Phishing Detection System
tests/test_database.py - Unit tests for the database module
Run with: pytest tests/test_database.py -v
"""

import sys
import os
import sqlite3
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# Use a test database so we don't touch the real one
TEST_DB = "test_phishing.db"

# Patch DB_PATH before importing database module
import database
database.DB_PATH = TEST_DB

from database import init_db, save_result, get_history, mark_ignored, mark_reported, get_stats


@pytest.fixture(autouse=True)
def setup_and_teardown():
    """Create fresh test DB before each test, remove after."""
    if os.path.exists(TEST_DB):
        os.remove(TEST_DB)
    init_db()
    yield
    if os.path.exists(TEST_DB):
        os.remove(TEST_DB)


class TestInitDB:

    def test_creates_db_file(self):
        assert os.path.exists(TEST_DB), "Database file should be created"

    def test_creates_analyses_table(self):
        conn = sqlite3.connect(TEST_DB)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='analyses'")
        result = cursor.fetchone()
        conn.close()
        assert result is not None, "analyses table should exist"

    def test_creates_reports_table(self):
        conn = sqlite3.connect(TEST_DB)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='reports'")
        result = cursor.fetchone()
        conn.close()
        assert result is not None, "reports table should exist"

    def test_creates_audit_log_table(self):
        conn = sqlite3.connect(TEST_DB)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='audit_log'")
        result = cursor.fetchone()
        conn.close()
        assert result is not None, "audit_log table should exist"

    def test_safe_to_call_twice(self):
        """init_db() uses IF NOT EXISTS so calling twice should not error."""
        init_db()
        assert os.path.exists(TEST_DB)


class TestSaveResult:

    def test_returns_integer_id(self):
        result_id = save_result("http://test.com", "url", 75.0, "PHISHING")
        assert isinstance(result_id, int), "save_result should return an integer ID"

    def test_id_increments(self):
        id1 = save_result("http://test1.com", "url", 20.0, "SAFE")
        id2 = save_result("http://test2.com", "url", 80.0, "PHISHING")
        assert id2 > id1, "IDs should increment"

    def test_data_is_stored(self):
        save_result("http://stored-test.com", "url", 55.0, "SUSPICIOUS")
        rows = get_history(1)
        assert len(rows) == 1
        assert rows[0][1] == "http://stored-test.com"
        assert rows[0][3] == 55.0
        assert rows[0][4] == "SUSPICIOUS"

    def test_default_status_is_pending(self):
        save_result("http://test.com", "url", 50.0, "SUSPICIOUS")
        rows = get_history(1)
        assert rows[0][6] == "pending", "Default status should be 'pending'"


class TestGetHistory:

    def test_returns_list(self):
        result = get_history()
        assert isinstance(result, list)

    def test_empty_when_no_records(self):
        result = get_history()
        assert len(result) == 0

    def test_returns_correct_count(self):
        for i in range(5):
            save_result(f"http://test{i}.com", "url", float(i * 10), "SAFE")
        rows = get_history(limit=3)
        assert len(rows) == 3, "Should respect the limit parameter"

    def test_newest_first(self):
        save_result("http://first.com", "url", 10.0, "SAFE")
        save_result("http://second.com", "url", 90.0, "PHISHING")
        rows = get_history()
        assert rows[0][1] == "http://second.com", "Most recent should be first"


class TestMarkIgnored:

    def test_status_changes_to_ignored(self):
        result_id = save_result("http://test.com", "url", 60.0, "SUSPICIOUS")
        mark_ignored(result_id)
        rows = get_history(1)
        assert rows[0][6] == "ignored"

    def test_audit_log_entry_created(self):
        result_id = save_result("http://test.com", "url", 60.0, "SUSPICIOUS")
        mark_ignored(result_id)
        conn = sqlite3.connect(TEST_DB)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM audit_log WHERE analysis_id=?", (result_id,))
        log = cursor.fetchone()
        conn.close()
        assert log is not None, "Audit log entry should be created"
        assert log[2] == "ignored"


class TestMarkReported:

    def test_status_changes_to_reported(self):
        result_id = save_result("http://phish.com", "url", 90.0, "PHISHING")
        mark_reported(result_id, "Suspicious URL / domain")
        rows = get_history(1)
        assert rows[0][6] == "reported"

    def test_report_saved_with_reason(self):
        result_id = save_result("http://phish.com", "url", 90.0, "PHISHING")
        mark_reported(result_id, "Fake login page")
        conn = sqlite3.connect(TEST_DB)
        cursor = conn.cursor()
        cursor.execute("SELECT reason FROM reports WHERE analysis_id=?", (result_id,))
        row = cursor.fetchone()
        conn.close()
        assert row is not None
        assert row[0] == "Fake login page"


class TestGetStats:

    def test_returns_dict(self):
        stats = get_stats()
        assert isinstance(stats, dict)

    def test_all_keys_present(self):
        stats = get_stats()
        for key in ["total", "safe", "suspicious", "phishing", "reported", "ignored"]:
            assert key in stats

    def test_counts_are_accurate(self):
        id1 = save_result("http://safe.com", "url", 10.0, "SAFE")
        id2 = save_result("http://phish.com", "url", 90.0, "PHISHING")
        mark_reported(id2, "Test")

        stats = get_stats()
        assert stats["total"] == 2
        assert stats["safe"] == 1
        assert stats["phishing"] == 1
        assert stats["reported"] == 1
