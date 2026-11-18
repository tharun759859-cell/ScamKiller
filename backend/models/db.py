"""
SCAM KILLER — SQLite Connection & Schema Management
Provides SQLite database initialization and connection handling.
"""

import sqlite3
import os
from typing import Generator

DB_FILE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scam_killer.db")


def get_db_connection() -> sqlite3.Connection:
    """Creates a database connection with dict-like row access."""
    conn = sqlite3.connect(DB_FILE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Initializes SQLite database tables and seeds initial data if empty."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # Telemetry Table (Strictly non-sensitive metadata)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id TEXT UNIQUE NOT NULL,
        scan_type TEXT NOT NULL,
        risk_category TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        time_ago TEXT DEFAULT 'Just now',
        display_item TEXT NOT NULL,
        content_status TEXT,
        url_status TEXT,
        screenshot_status TEXT,
        intel_status TEXT,
        indicator_count INTEGER DEFAULT 0,
        explanation TEXT,
        metadata_json TEXT
    );
    """)

    # Community Threat Reports Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS community_reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        report_id TEXT UNIQUE NOT NULL,
        category TEXT NOT NULL,
        title TEXT NOT NULL,
        reported_item TEXT NOT NULL,
        date_reported TEXT NOT NULL,
        upvotes INTEGER DEFAULT 0,
        risk_level TEXT NOT NULL,
        status TEXT NOT NULL,
        description TEXT,
        is_demo INTEGER DEFAULT 0,
        source TEXT DEFAULT 'community'
    );
    """)

    # Safe column migrations for existing SQLite databases
    try:
        cursor.execute("ALTER TABLE community_reports ADD COLUMN is_demo INTEGER DEFAULT 0")
    except sqlite3.OperationalError:
        pass
    try:
        cursor.execute("ALTER TABLE community_reports ADD COLUMN source TEXT DEFAULT 'community'")
    except sqlite3.OperationalError:
        pass

    for col_def in [
        "source_type TEXT DEFAULT 'text'",
        "confidence REAL DEFAULT 0.8",
        "ai_summary TEXT DEFAULT ''",
        "structured_data TEXT DEFAULT ''"
    ]:
        try:
            cursor.execute(f"ALTER TABLE scans ADD COLUMN {col_def}")
        except sqlite3.OperationalError:
            pass

    conn.commit()
    conn.close()
