from __future__ import annotations

import sqlite3
from pathlib import Path

import pandas as pd


def get_connection(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS processed_files (
            file_name TEXT PRIMARY KEY,
            file_type TEXT NOT NULL,
            processed_at TEXT NOT NULL
        )
        """
    )

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS dmarc_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            report_id TEXT,
            org_name TEXT,
            domain TEXT,
            report_start INTEGER,
            report_end INTEGER,
            source_ip TEXT,
            message_count INTEGER,
            disposition TEXT,
            dkim_result TEXT,
            spf_result TEXT,
            header_from TEXT,
            auth_dkim_domain TEXT,
            auth_dkim_result TEXT,
            auth_spf_domain TEXT,
            auth_spf_result TEXT,
            reverse_dns TEXT,
            risk_label TEXT,
            risk_score INTEGER,
            xml_file_name TEXT,
            zip_file_name TEXT,
            ingested_at TEXT
        )
        """
    )
    conn.commit()


def has_processed_file(conn: sqlite3.Connection, file_name: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM processed_files WHERE file_name = ?", (file_name,)
    ).fetchone()
    return row is not None


def mark_processed_file(conn: sqlite3.Connection, file_name: str, file_type: str) -> None:
    conn.execute(
        """
        INSERT OR REPLACE INTO processed_files (file_name, file_type, processed_at)
        VALUES (?, ?, datetime('now'))
        """,
        (file_name, file_type),
    )
    conn.commit()


def reset_ingestion_state(conn: sqlite3.Connection) -> None:
    """Clear all ingest history and parsed data for a full rebuild."""
    conn.execute("DELETE FROM dmarc_records")
    conn.execute("DELETE FROM processed_files")
    conn.commit()


def insert_records(conn: sqlite3.Connection, rows: list[dict]) -> int:
    if not rows:
        return 0

    conn.executemany(
        """
        INSERT INTO dmarc_records (
            report_id, org_name, domain, report_start, report_end,
            source_ip, message_count, disposition, dkim_result, spf_result,
            header_from, auth_dkim_domain, auth_dkim_result,
            auth_spf_domain, auth_spf_result, reverse_dns,
            risk_label, risk_score, xml_file_name, zip_file_name, ingested_at
        )
        VALUES (
            :report_id, :org_name, :domain, :report_start, :report_end,
            :source_ip, :message_count, :disposition, :dkim_result, :spf_result,
            :header_from, :auth_dkim_domain, :auth_dkim_result,
            :auth_spf_domain, :auth_spf_result, :reverse_dns,
            :risk_label, :risk_score, :xml_file_name, :zip_file_name, datetime('now')
        )
        """,
        rows,
    )
    conn.commit()
    return len(rows)


def fetch_summary_by_day(conn: sqlite3.Connection) -> pd.DataFrame:
    query = """
    SELECT
        date(report_end, 'unixepoch') AS report_day,
        SUM(message_count) AS total_messages,
        SUM(CASE WHEN dkim_result = 'pass' AND spf_result = 'pass' THEN message_count ELSE 0 END) AS pass_count,
        SUM(CASE WHEN disposition IN ('quarantine', 'reject') OR dkim_result != 'pass' OR spf_result != 'pass' THEN message_count ELSE 0 END) AS fail_like_count,
        SUM(CASE WHEN spf_result = 'softfail' THEN message_count ELSE 0 END) AS softfail_count
    FROM dmarc_records
    GROUP BY date(report_end, 'unixepoch')
    ORDER BY report_day DESC
    """
    return pd.read_sql_query(query, conn)


def fetch_domain_summary(conn: sqlite3.Connection) -> pd.DataFrame:
    query = """
    SELECT
        COALESCE(NULLIF(header_from, ''), domain) AS domain_name,
        SUM(message_count) AS total_messages,
        SUM(CASE WHEN dkim_result = 'pass' AND spf_result = 'pass' THEN message_count ELSE 0 END) AS pass_count,
        SUM(CASE WHEN disposition IN ('quarantine', 'reject') OR dkim_result != 'pass' OR spf_result != 'pass' THEN message_count ELSE 0 END) AS fail_like_count
    FROM dmarc_records
    GROUP BY domain_name
    ORDER BY total_messages DESC
    """
    return pd.read_sql_query(query, conn)


def fetch_suspicious_ips(conn: sqlite3.Connection) -> pd.DataFrame:
    query = """
    SELECT
        source_ip,
        COALESCE(reverse_dns, '') AS reverse_dns,
        SUM(message_count) AS total_messages,
        MAX(risk_score) AS max_risk_score,
        MAX(risk_label) AS risk_label,
        SUM(CASE WHEN dkim_result != 'pass' THEN message_count ELSE 0 END) AS dkim_fail_messages,
        SUM(CASE WHEN spf_result != 'pass' THEN message_count ELSE 0 END) AS spf_fail_messages,
        GROUP_CONCAT(DISTINCT COALESCE(NULLIF(header_from, ''), domain)) AS domains_seen
    FROM dmarc_records
    GROUP BY source_ip, reverse_dns
    ORDER BY max_risk_score DESC, total_messages DESC
    """
    return pd.read_sql_query(query, conn)


def fetch_raw_records(conn: sqlite3.Connection) -> pd.DataFrame:
    query = """
    SELECT
        id,
        datetime(report_start, 'unixepoch') AS report_start,
        datetime(report_end, 'unixepoch') AS report_end,
        org_name,
        domain,
        header_from,
        source_ip,
        reverse_dns,
        message_count,
        disposition,
        dkim_result,
        spf_result,
        risk_label,
        risk_score,
        xml_file_name,
        zip_file_name,
        ingested_at
    FROM dmarc_records
    ORDER BY report_end DESC, id DESC
    """
    return pd.read_sql_query(query, conn)
