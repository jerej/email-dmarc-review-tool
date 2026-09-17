from __future__ import annotations

import pandas as pd
import streamlit as st

from dmarc_review.config import load_config
from dmarc_review.db import (
    fetch_raw_records,
    fetch_summary_by_day,
    get_connection,
    init_db,
    reset_ingestion_state,
)
from dmarc_review.gmail_fetch import GmailFetchError, fetch_gmail_dmarc_attachments
from dmarc_review.ingest import ingest_from_watched_folder


st.set_page_config(page_title="DMARC Daily Review", layout="wide")


def clear_extracted_xml_dir(extracted_xml_dir) -> int:
    """Remove extracted XML files so force rebuild starts from a clean staging area."""
    removed = 0
    for child in extracted_xml_dir.iterdir():
        if child.is_file() and child.name != ".gitkeep":
            child.unlink()
            removed += 1
    return removed


def _domain_name_series(df: pd.DataFrame) -> pd.Series:
    header_from = df["header_from"].fillna("").astype(str).str.strip()
    return header_from.where(header_from != "", df["domain"].fillna("").astype(str))


def _build_domain_summary(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return pd.DataFrame(columns=["domain_name", "total_messages", "pass_count", "fail_like_count"])

    working = df.copy()
    working["message_count"] = pd.to_numeric(working["message_count"], errors="coerce").fillna(0).astype(int)
    working["domain_name"] = _domain_name_series(working)
    pass_mask = (working["dkim_result"] == "pass") & (working["spf_result"] == "pass")
    fail_like_mask = (
        working["disposition"].isin(["quarantine", "reject"])
        | (working["dkim_result"] != "pass")
        | (working["spf_result"] != "pass")
    )

    grouped = (
        working.groupby("domain_name", dropna=False)
        .apply(
            lambda g: pd.Series(
                {
                    "total_messages": int(g["message_count"].sum()),
                    "pass_count": int(g.loc[pass_mask.loc[g.index], "message_count"].sum()),
                    "fail_like_count": int(g.loc[fail_like_mask.loc[g.index], "message_count"].sum()),
                }
            )
        )
        .reset_index()
        .sort_values("total_messages", ascending=False)
    )

    return grouped


def _build_suspicious_ips(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return pd.DataFrame(
            columns=[
                "source_ip",
                "reverse_dns",
                "total_messages",
                "max_risk_score",
                "risk_label",
                "dkim_fail_messages",
                "spf_fail_messages",
                "domains_seen",
            ]
        )

    working = df.copy()
    working["message_count"] = pd.to_numeric(working["message_count"], errors="coerce").fillna(0).astype(int)
    working["risk_score"] = pd.to_numeric(working["risk_score"], errors="coerce").fillna(0).astype(int)
    working["reverse_dns"] = working["reverse_dns"].fillna("")
    working["domain_name"] = _domain_name_series(working)

    grouped = (
        working.groupby(["source_ip", "reverse_dns"], dropna=False)
        .apply(
            lambda g: pd.Series(
                {
                    "total_messages": int(g["message_count"].sum()),
                    "max_risk_score": int(g["risk_score"].max()),
                    "risk_label": str(g["risk_label"].max() if not g["risk_label"].empty else ""),
                    "dkim_fail_messages": int(g.loc[g["dkim_result"] != "pass", "message_count"].sum()),
                    "spf_fail_messages": int(g.loc[g["spf_result"] != "pass", "message_count"].sum()),
                    "domains_seen": ",".join(sorted({str(v) for v in g["domain_name"].fillna("") if str(v)})),
                }
            )
        )
        .reset_index()
        .sort_values(["max_risk_score", "total_messages"], ascending=[False, False])
    )

    return grouped


def run() -> None:
    st.title("DMARC Daily Review Dashboard")
    st.caption("Local prototype: fetches Gmail DMARC attachments, ingests compressed reports, and highlights suspicious senders.")

    cfg = load_config()
    conn = get_connection(cfg.db_path)
    init_db(conn)

    with st.sidebar:
        st.subheader("Folders")
        st.write(f"Incoming folder: {cfg.incoming_compressed_dir}")
        st.write(f"Extracted XML folder: {cfg.extracted_xml_dir}")
        st.write(f"SQLite DB: {cfg.db_path}")
        st.write(f"Gmail query: {cfg.gmail_label_query}")
        table_range = st.segmented_control(
            "Table data range",
            ["All time", "Recent (last 24 hours)", "Last 7 days"],
            default="All time",
        )

        fetch_gmail_clicked = st.button("Fetch Gmail DMARC Attachments")
        ingest_clicked = st.button("Scan Watched Folder Now", type="primary")
        st.divider()
        st.subheader("Maintenance")
        confirm_force_rebuild = st.checkbox(
            "I understand this clears parsed data and ingest history before rebuilding."
        )
        force_rebuild_clicked = st.button("Force Rebuild From Watched Folder")

    if fetch_gmail_clicked:
        try:
            gmail_stats = fetch_gmail_dmarc_attachments(
                conn=conn,
                incoming_dir=cfg.incoming_compressed_dir,
                credentials_path=cfg.gmail_credentials_path,
                token_path=cfg.gmail_token_path,
                query=cfg.gmail_label_query,
                max_results=cfg.gmail_max_results,
                mark_as_read=cfg.gmail_mark_as_read,
            )
            st.success(
                "Gmail fetch complete. "
                f"Messages seen: {gmail_stats.messages_seen}, new messages: {gmail_stats.messages_new}, "
                f"attachments saved: {gmail_stats.attachments_saved}, duplicate attachments skipped: {gmail_stats.attachments_duplicate}, "
                f"messages marked read: {gmail_stats.messages_marked_read}."
            )
            if gmail_stats.errors:
                for err in gmail_stats.errors:
                    st.warning(err)

            if gmail_stats.attachments_saved > 0:
                stats = ingest_from_watched_folder(
                    conn=conn,
                    watched_input_dirs=cfg.watched_input_dirs,
                    extracted_xml_dir=cfg.extracted_xml_dir,
                )
                st.success(
                    "Auto-ingest after Gmail fetch complete. "
                    f"New compressed files: {stats.zip_files_new}, duplicate compressed files skipped: {stats.zip_files_duplicate}, "
                    f"new XML files: {stats.xml_files_new}, duplicate XML files skipped: {stats.xml_files_duplicate}, "
                    f"records inserted: {stats.records_inserted}."
                )
                if stats.errors:
                    for err in stats.errors:
                        st.warning(err)
        except GmailFetchError as exc:
            st.error(str(exc))
    elif force_rebuild_clicked:
        if not confirm_force_rebuild:
            st.error("Enable the confirmation checkbox before running a force rebuild.")
        else:
            reset_ingestion_state(conn)
            removed_files = clear_extracted_xml_dir(cfg.extracted_xml_dir)
            stats = ingest_from_watched_folder(
                conn=conn,
                watched_input_dirs=cfg.watched_input_dirs,
                extracted_xml_dir=cfg.extracted_xml_dir,
            )
            st.success(
                "Force rebuild complete. "
                f"Extracted XML files removed: {removed_files}. "
                f"New compressed files: {stats.zip_files_new}, duplicate compressed files skipped: {stats.zip_files_duplicate}, "
                f"new XML files: {stats.xml_files_new}, duplicate XML files skipped: {stats.xml_files_duplicate}, "
                f"records inserted: {stats.records_inserted}."
            )
            if stats.errors:
                for err in stats.errors:
                    st.warning(err)
    elif ingest_clicked:
        stats = ingest_from_watched_folder(
            conn=conn,
            watched_input_dirs=cfg.watched_input_dirs,
            extracted_xml_dir=cfg.extracted_xml_dir,
        )
        st.success(
            "Scan complete. "
            f"New compressed files: {stats.zip_files_new}, duplicate compressed files skipped: {stats.zip_files_duplicate}, "
            f"new XML files: {stats.xml_files_new}, duplicate XML files skipped: {stats.xml_files_duplicate}, "
            f"records inserted: {stats.records_inserted}."
        )
        if stats.errors:
            for err in stats.errors:
                st.warning(err)

    day_summary = fetch_summary_by_day(conn)
    raw_records = fetch_raw_records(conn)

    if raw_records.empty:
        st.info("No records yet. Drop compressed report files into the incoming folder and click 'Scan Watched Folder Now'.")
        return

    st.subheader("Daily Snapshot")
    latest = day_summary.iloc[0]
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Messages", int(latest["total_messages"] or 0))
    col2.metric("Pass Count", int(latest["pass_count"] or 0))
    col3.metric("Fail-like Count", int(latest["fail_like_count"] or 0))
    col4.metric("Softfail Count", int(latest["softfail_count"] or 0))

    st.subheader("Recent Trend")
    st.line_chart(
        day_summary.set_index("report_day")[["total_messages", "pass_count", "fail_like_count", "softfail_count"]]
    )

    if table_range == "Recent (last 24 hours)":
        cutoff = pd.Timestamp.utcnow().tz_localize(None) - pd.Timedelta(hours=24)
        report_end_ts = pd.to_datetime(raw_records["report_end"], errors="coerce")
        filtered_records = raw_records.loc[report_end_ts >= cutoff].copy()
        st.caption("Tables filtered to reports ending in the last 24 hours.")
    elif table_range == "Last 7 days":
        cutoff = pd.Timestamp.utcnow().tz_localize(None) - pd.Timedelta(days=7)
        report_end_ts = pd.to_datetime(raw_records["report_end"], errors="coerce")
        filtered_records = raw_records.loc[report_end_ts >= cutoff].copy()
        st.caption("Tables filtered to reports ending in the last 7 days.")
    else:
        filtered_records = raw_records
        st.caption("Tables showing all available records.")

    domain_summary = _build_domain_summary(filtered_records)
    suspicious_ips = _build_suspicious_ips(filtered_records)

    st.subheader("Domain Summary")
    st.dataframe(domain_summary)

    st.subheader("Suspicious Source IPs")
    st.dataframe(suspicious_ips)

    st.subheader("Raw Records")
    st.dataframe(raw_records)


if __name__ == "__main__":
    run()
