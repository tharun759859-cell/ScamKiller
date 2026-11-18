"""
SCAM KILLER — Universal Database Connection & Schema Management
Supports PostgreSQL (Production / DATABASE_URL) and SQLite (Local / scam_killer.db).
"""

import os
import sqlite3
import logging
from typing import Optional, Any

logger = logging.getLogger("scam_killer.database")

DB_DIR = os.path.dirname(os.path.abspath(__file__))
SQLITE_DB_PATH = os.path.join(DB_DIR, "scam_killer.db")
SCHEMA_SQL_PATH = os.path.join(DB_DIR, "schema.sql")


def is_postgres() -> bool:
    """Checks if a PostgreSQL connection URL is present in the environment."""
    url = os.environ.get("DATABASE_URL", "").strip().lower()
    return url.startswith("postgres://") or url.startswith("postgresql://")


class PostgresCursorWrapper:
    """Adapts '?' parameter placeholders to '%s' for PostgreSQL transparently."""

    def __init__(self, cursor):
        self._cursor = cursor

    def execute(self, sql: str, params: Optional[Any] = None):
        if params is not None:
            pg_sql = sql.replace("?", "%s")
            return self._cursor.execute(pg_sql, params)
        return self._cursor.execute(sql)

    def executemany(self, sql: str, params_list: Any):
        pg_sql = sql.replace("?", "%s")
        return self._cursor.executemany(pg_sql, params_list)

    def fetchone(self):
        return self._cursor.fetchone()

    def fetchall(self):
        return self._cursor.fetchall()

    def fetchmany(self, size: Optional[int] = None):
        return self._cursor.fetchmany(size) if size else self._cursor.fetchmany()

    @property
    def rowcount(self):
        return self._cursor.rowcount

    def __iter__(self):
        return iter(self._cursor)


class PostgresConnectionWrapper:
    """Wraps psycopg2 connection to provide dict-like row access and SQLite compatibility."""

    def __init__(self, conn):
        self._conn = conn

    def cursor(self):
        from psycopg2.extras import RealDictCursor
        return PostgresCursorWrapper(self._conn.cursor(cursor_factory=RealDictCursor))

    def commit(self):
        return self._conn.commit()

    def rollback(self):
        return self._conn.rollback()

    def close(self):
        return self._conn.close()


def get_db_connection():
    """
    Returns an active database connection.
    Connects to PostgreSQL if DATABASE_URL is set, otherwise falls back to local SQLite.
    """
    raw_url = os.environ.get("DATABASE_URL", "").strip()
    if is_postgres():
        try:
            import psycopg2
            # Normalizes render/heroku postgres:// to postgresql://
            pg_url = raw_url
            if pg_url.startswith("postgres://"):
                pg_url = pg_url.replace("postgres://", "postgresql://", 1)
            conn = psycopg2.connect(pg_url)
            return PostgresConnectionWrapper(conn)
        except Exception as exc:
            logger.warning(f"PostgreSQL connection error: {exc}. Falling back to SQLite.")

    # Default Local SQLite
    conn = sqlite3.connect(SQLITE_DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Initializes tables for either PostgreSQL or SQLite."""
    if is_postgres():
        try:
            conn = get_db_connection()
            if isinstance(conn, PostgresConnectionWrapper):
                cursor = conn.cursor()
                if os.path.exists(SCHEMA_SQL_PATH):
                    with open(SCHEMA_SQL_PATH, "r", encoding="utf-8") as f:
                        cursor.execute(f.read())
                    conn.commit()
                conn.close()
                logger.info("PostgreSQL database tables initialized successfully.")
                return
        except Exception as exc:
            logger.warning(f"Failed to execute schema.sql on PostgreSQL: {exc}")

    # Fallback / Local SQLite Schema Initialization
    conn = sqlite3.connect(SQLITE_DB_PATH)
    cursor = conn.cursor()

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

    for col_def in [
        "source_type TEXT DEFAULT 'text'",
        "confidence REAL DEFAULT 0.8",
        "ai_summary TEXT DEFAULT ''",
        "structured_data TEXT DEFAULT ''",
        "full_report_json TEXT DEFAULT ''",
        "pattern_fingerprint TEXT DEFAULT ''",
        "impersonated_entity TEXT DEFAULT 'None'",
        "category TEXT DEFAULT 'General Phishing'",
        "message_theme TEXT DEFAULT ''",
        "urgency_or_reward_pattern TEXT DEFAULT ''",
        "requested_action TEXT DEFAULT ''"
    ]:
        try:
            cursor.execute(f"ALTER TABLE scans ADD COLUMN {col_def}")
        except sqlite3.OperationalError:
            pass

    conn.commit()
    conn.close()
