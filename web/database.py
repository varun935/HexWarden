"""SQLite persistence layer for the HexWarden web dashboard.

One table, `scans`, tracks every upload from creation through completion
(or failure). A fresh `sqlite3.connect()` is opened and closed on every
call rather than held open across requests: the dashboard's write volume
is low (one row per scan, a handful of updates as the pipeline
progresses) and this sidesteps sqlite3's default same-thread restriction
entirely -- the background pipeline thread and Flask's request threads
both write to this table, and each gets its own short-lived connection
rather than sharing one across threads.

Inputs:
    Scan metadata and results, written incrementally as
    `web/app.py`'s background pipeline thread progresses through a scan.

Outputs:
    Row dicts read back by `web/app.py`'s routes to serve scan status,
    reports, and history.
"""

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import config

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    firmware_filename TEXT NOT NULL,
    firmware_size INTEGER NOT NULL,
    has_golden INTEGER NOT NULL DEFAULT 0,
    has_pcap INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'pending',
    current_step TEXT,
    verdict TEXT,
    total_score INTEGER,
    findings_json TEXT,
    score_json TEXT,
    entropy_plot_path TEXT,
    error_message TEXT
);
"""

_CONNECT_TIMEOUT_SECONDS = 10


def _connect() -> sqlite3.Connection:
    """Open a fresh connection to the scans database.

    Returns:
        A `sqlite3.Connection` with row access by column name.

    Raises:
        sqlite3.Error: If the database file cannot be opened.
    """
    config.WEB_DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(str(config.WEB_DATABASE_PATH), timeout=_CONNECT_TIMEOUT_SECONDS)
    connection.row_factory = sqlite3.Row
    return connection


def init_db() -> None:
    """Create the `scans` table if it doesn't already exist.

    Args:
        None.

    Returns:
        None.

    Raises:
        sqlite3.Error: If the table cannot be created.
    """
    with _connect() as connection:
        connection.execute(_SCHEMA)


def _now() -> str:
    """Return the current UTC time as an ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()


def create_scan(
    scan_id: str,
    firmware_filename: str,
    firmware_size: int,
    has_golden: bool,
    has_pcap: bool,
) -> None:
    """Insert a new scan row with status="pending".

    Args:
        scan_id: UUID identifying this scan.
        firmware_filename: Original uploaded firmware filename.
        firmware_size: Firmware file size in bytes.
        has_golden: Whether a golden reference firmware was uploaded.
        has_pcap: Whether a network capture was uploaded.

    Returns:
        None.

    Raises:
        sqlite3.Error: If the insert fails.
    """
    with _connect() as connection:
        connection.execute(
            """
            INSERT INTO scans (
                id, created_at, firmware_filename, firmware_size,
                has_golden, has_pcap, status
            ) VALUES (?, ?, ?, ?, ?, ?, 'pending')
            """,
            (scan_id, _now(), firmware_filename, firmware_size, int(has_golden), int(has_pcap)),
        )


def update_scan_status(scan_id: str, status: str) -> None:
    """Update a scan's status (e.g. "running").

    Args:
        scan_id: UUID identifying the scan.
        status: New status value.

    Returns:
        None.

    Raises:
        sqlite3.Error: If the update fails.
    """
    with _connect() as connection:
        connection.execute("UPDATE scans SET status = ? WHERE id = ?", (status, scan_id))


def update_scan_step(scan_id: str, current_step: str) -> None:
    """Update a scan's human-readable current pipeline step.

    Args:
        scan_id: UUID identifying the scan.
        current_step: Human-readable description of the step in progress.

    Returns:
        None.

    Raises:
        sqlite3.Error: If the update fails.
    """
    with _connect() as connection:
        connection.execute(
            "UPDATE scans SET current_step = ? WHERE id = ?", (current_step, scan_id)
        )


def complete_scan(
    scan_id: str,
    verdict: str,
    total_score: int,
    findings_json: str,
    score_json: str,
    entropy_plot_path: Optional[str],
) -> None:
    """Mark a scan complete and store its final results.

    Args:
        scan_id: UUID identifying the scan.
        verdict: "LOW", "MEDIUM", "HIGH", or "CRITICAL".
        total_score: Combined weighted risk score.
        findings_json: JSON-serialized `List[Finding]`.
        score_json: JSON-serialized `ScanScore`.
        entropy_plot_path: Path to the saved entropy plot PNG, or None.

    Returns:
        None.

    Raises:
        sqlite3.Error: If the update fails.
    """
    with _connect() as connection:
        connection.execute(
            """
            UPDATE scans
            SET status = 'complete', current_step = 'Complete', verdict = ?,
                total_score = ?, findings_json = ?, score_json = ?, entropy_plot_path = ?
            WHERE id = ?
            """,
            (verdict, total_score, findings_json, score_json, entropy_plot_path, scan_id),
        )


def fail_scan(scan_id: str, error_message: str) -> None:
    """Mark a scan as failed with an error message.

    Args:
        scan_id: UUID identifying the scan.
        error_message: Human-readable error description.

    Returns:
        None.

    Raises:
        sqlite3.Error: If the update fails.
    """
    with _connect() as connection:
        connection.execute(
            "UPDATE scans SET status = 'error', current_step = 'Failed', error_message = ? "
            "WHERE id = ?",
            (error_message, scan_id),
        )


def get_scan(scan_id: str) -> Optional[Dict[str, Any]]:
    """Fetch one scan row.

    Args:
        scan_id: UUID identifying the scan.

    Returns:
        Dict of column name -> value, or None if no scan with that id
        exists.

    Raises:
        sqlite3.Error: If the query fails.
    """
    with _connect() as connection:
        row = connection.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    return dict(row) if row is not None else None


def list_scans(limit: int = 20) -> List[Dict[str, Any]]:
    """List the most recent scans, newest first.

    Args:
        limit: Maximum number of scans to return.

    Returns:
        List of scan row dicts, ordered by `created_at` descending.

    Raises:
        sqlite3.Error: If the query fails.
    """
    with _connect() as connection:
        rows = connection.execute(
            "SELECT * FROM scans ORDER BY created_at DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(row) for row in rows]
