"""
GonePhishing - Phishing Detection System
database.py - SQLite database setup and all query functions
"""

import sqlite3
import os
from datetime import datetime

DB_PATH = "phishing.db"


# ── Initialise database ────────────────────────────────────────────────────────
def init_db():
    """
    Create the database and tables if they don't already exist.
    Safe to call every time the app starts.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Main analyses table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS analyses (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            input_text  TEXT    NOT NULL,
            input_type  TEXT    NOT NULL,
            score       REAL    NOT NULL,
            verdict     TEXT    NOT NULL,
            timestamp   TEXT    NOT NULL,
            status      TEXT    DEFAULT 'pending'
        )
    """)

    # Reports table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS reports (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            analysis_id INTEGER NOT NULL,
            reason      TEXT    NOT NULL,
            reported_at TEXT    NOT NULL,
            FOREIGN KEY (analysis_id) REFERENCES analyses(id)
        )
    """)

    # Audit log table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            analysis_id INTEGER NOT NULL,
            action      TEXT    NOT NULL,
            detail      TEXT,
            actioned_at TEXT    NOT NULL
        )
    """)

    conn.commit()
    conn.close()
    print(f"[Database] Initialised at: {os.path.abspath(DB_PATH)}")


# ── Save a new analysis result ─────────────────────────────────────────────────
def save_result(input_text, input_type, score, verdict):
    """
    Save an analysis result to the database.

    Returns:
        int: The ID of the newly created record
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute("""
        INSERT INTO analyses (input_text, input_type, score, verdict, timestamp, status)
        VALUES (?, ?, ?, ?, ?, 'pending')
    """, (input_text, input_type, score, verdict, timestamp))

    new_id = cursor.lastrowid
    conn.commit()
    conn.close()

    print(f"[Database] Saved result ID={new_id}  verdict={verdict}  score={score:.1f}")
    return new_id


# ── Get history ────────────────────────────────────────────────────────────────
def get_history(limit=50):
    """
    Retrieve the most recent analysis results.

    Returns:
        list of tuples: (id, input_text, input_type, score, verdict, timestamp, status)
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, input_text, input_type, score, verdict, timestamp, status
        FROM analyses
        ORDER BY id DESC
        LIMIT ?
    """, (limit,))

    rows = cursor.fetchall()
    conn.close()
    return rows


# ── Mark as ignored ────────────────────────────────────────────────────────────
def mark_ignored(analysis_id):
    """
    Mark an analysis result as ignored and log the action.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE analyses SET status = 'ignored' WHERE id = ?
    """, (analysis_id,))

    cursor.execute("""
        INSERT INTO audit_log (analysis_id, action, detail, actioned_at)
        VALUES (?, 'ignored', 'User marked as ignored', ?)
    """, (analysis_id, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))

    conn.commit()
    conn.close()
    print(f"[Database] Analysis ID={analysis_id} marked as ignored.")


# ── Mark as reported ───────────────────────────────────────────────────────────
def mark_reported(analysis_id, reason):
    """
    Mark an analysis result as reported, save the report reason,
    and log the action.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Update status
    cursor.execute("""
        UPDATE analyses SET status = 'reported' WHERE id = ?
    """, (analysis_id,))

    # Save report
    cursor.execute("""
        INSERT INTO reports (analysis_id, reason, reported_at)
        VALUES (?, ?, ?)
    """, (analysis_id, reason, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))

    # Audit log
    cursor.execute("""
        INSERT INTO audit_log (analysis_id, action, detail, actioned_at)
        VALUES (?, 'reported', ?, ?)
    """, (analysis_id, reason, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))

    conn.commit()
    conn.close()
    print(f"[Database] Analysis ID={analysis_id} reported. Reason: {reason}")


# ── Get stats summary ──────────────────────────────────────────────────────────
def get_stats():
    """
    Return summary statistics from the database.

    Returns:
        dict: counts of total, safe, suspicious, phishing, reported, ignored
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM analyses")
    total = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM analyses WHERE verdict = 'SAFE'")
    safe = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM analyses WHERE verdict = 'SUSPICIOUS'")
    suspicious = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM analyses WHERE verdict = 'PHISHING'")
    phishing = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM analyses WHERE status = 'reported'")
    reported = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM analyses WHERE status = 'ignored'")
    ignored = cursor.fetchone()[0]

    conn.close()

    return {
        "total": total,
        "safe": safe,
        "suspicious": suspicious,
        "phishing": phishing,
        "reported": reported,
        "ignored": ignored
    }


# ── Quick test ─────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    init_db()
    test_id = save_result("http://test-phishing.xyz/login", "url", 87.5, "PHISHING")
    print(f"Saved test record with ID: {test_id}")

    rows = get_history(5)
    print(f"History ({len(rows)} rows):")
    for row in rows:
        print(f"  {row}")

    mark_ignored(test_id)
    stats = get_stats()
    print(f"Stats: {stats}")
