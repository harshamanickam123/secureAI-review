import logging
import os
from contextlib import contextmanager
from typing import Any, Dict, List, Optional
import mysql.connector
from mysql.connector import pooling
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

# Schema DDL definitions
CREATE_TABLES_SQL = """
CREATE TABLE IF NOT EXISTS scans (
    id INT AUTO_INCREMENT PRIMARY KEY,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    source_type VARCHAR(50) NOT NULL,
    source_ref TEXT NULL,
    language VARCHAR(50) NOT NULL,
    status VARCHAR(50) DEFAULT 'processing'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS findings (
    id INT AUTO_INCREMENT PRIMARY KEY,
    scan_id INT NOT NULL,
    rule_id VARCHAR(255) NOT NULL,
    severity VARCHAR(50) NOT NULL,
    file_path VARCHAR(255) NOT NULL,
    line_number INT NOT NULL,
    raw_message TEXT NOT NULL,
    ai_explanation TEXT NULL,
    ai_fix_suggestion TEXT NULL,
    ai_confidence VARCHAR(50) NULL,
    severity_conflict BOOLEAN DEFAULT FALSE,
    source VARCHAR(50) DEFAULT 'semgrep',
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
"""

_pool: Optional[pooling.MySQLConnectionPool] = None


def get_db_pool() -> Optional[pooling.MySQLConnectionPool]:
    """Initializes or retrieves the MySQL connection pool."""
    global _pool
    if _pool is not None:
        return _pool

    host = os.getenv("MYSQL_HOST", "localhost")
    user = os.getenv("MYSQL_USER", "root")
    password = os.getenv("MYSQL_PASSWORD", "")
    database = os.getenv("MYSQL_DB", "secureai_review")
    port = int(os.getenv("MYSQL_PORT", 3306))

    try:
        _pool = pooling.MySQLConnectionPool(
            pool_name="secureai_pool",
            pool_size=10,
            pool_reset_session=True,
            host=host,
            user=user,
            password=password,
            database=database,
            port=port,
        )
        logger.info(f"MySQL connection pool initialized for database '{database}' on {host}:{port}")
        return _pool
    except Exception as e:
        logger.warning(f"Could not connect to MySQL ({host}:{port}/{database}): {e}")
        return None


@contextmanager
def get_db_cursor(dictionary: bool = False, commit: bool = True):
    """Context manager for obtaining a pooled database connection and cursor."""
    pool = get_db_pool()
    if pool is None:
        raise RuntimeError("Database pool is not available. Please verify MySQL configuration.")

    conn = pool.get_connection()
    cursor = conn.cursor(dictionary=dictionary)
    try:
        yield cursor
        if commit:
            conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        cursor.close()
        conn.close()


def create_scan(source_type: str, source_ref: str, language: str) -> int:
    """Inserts a new scan row with status 'processing' and returns scan_id."""
    sql = """
    INSERT INTO scans (source_type, source_ref, language, status)
    VALUES (%s, %s, %s, 'processing')
    """
    with get_db_cursor() as cursor:
        cursor.execute(sql, (source_type, source_ref, language))
        return cursor.lastrowid


def update_scan_status(scan_id: int, status: str) -> None:
    """Updates the status of an existing scan."""
    sql = "UPDATE scans SET status = %s WHERE id = %s"
    with get_db_cursor() as cursor:
        cursor.execute(sql, (status, scan_id))


def insert_findings(scan_id: int, findings: List[Dict[str, Any]]) -> None:
    """Bulk inserts findings for a given scan_id."""
    if not findings:
        return

    sql = """
    INSERT INTO findings (
        scan_id, rule_id, severity, file_path, line_number,
        raw_message, ai_explanation, ai_fix_suggestion,
        ai_confidence, severity_conflict, source
    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """

    records = [
        (
            scan_id,
            f.get("rule_id", "unknown"),
            f.get("severity", "WARNING"),
            f.get("file_path", "source"),
            f.get("line_number", 1),
            f.get("raw_message", ""),
            f.get("ai_explanation"),
            f.get("ai_fix_suggestion"),
            f.get("ai_confidence"),
            bool(f.get("severity_conflict", False)),
            f.get("source", "semgrep"),
        )
        for f in findings
    ]

    with get_db_cursor() as cursor:
        cursor.executemany(sql, records)


def get_scan(scan_id: int) -> Optional[Dict[str, Any]]:
    """Fetches scan details and all associated findings."""
    scan_sql = "SELECT id, created_at, source_type, language, status FROM scans WHERE id = %s"
    findings_sql = """
    SELECT rule_id, severity, file_path, line_number, raw_message,
           ai_explanation, ai_fix_suggestion, ai_confidence, severity_conflict, source
    FROM findings
    WHERE scan_id = %s
    ORDER BY id ASC
    """

    with get_db_cursor(dictionary=True, commit=False) as cursor:
        cursor.execute(scan_sql, (scan_id,))
        scan = cursor.fetchone()
        if not scan:
            return None

        cursor.execute(findings_sql, (scan_id,))
        findings_rows = cursor.fetchall()

        # Convert boolean flags properly
        findings = []
        for r in findings_rows:
            r["severity_conflict"] = bool(r["severity_conflict"])
            r["source"] = r.get("source") or "semgrep"
            findings.append(r)

        return {
            "scan_id": scan["id"],
            "status": scan["status"],
            "language": scan["language"],
            "source_type": scan["source_type"],
            "findings": findings,
        }
