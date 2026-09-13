from __future__ import annotations

from dmarc_review.config import load_config
from dmarc_review.db import get_connection, init_db
from dmarc_review.gmail_fetch import GmailFetchError, fetch_gmail_dmarc_attachments
from dmarc_review.ingest import ingest_from_watched_folder


def main() -> int:
    cfg = load_config()
    conn = get_connection(cfg.db_path)
    init_db(conn)

    try:
        gmail_stats = fetch_gmail_dmarc_attachments(
            conn=conn,
            incoming_dir=cfg.incoming_compressed_dir,
            credentials_path=cfg.gmail_credentials_path,
            token_path=cfg.gmail_token_path,
            query=cfg.gmail_label_query,
            max_results=cfg.gmail_max_results,
        )
    except GmailFetchError as exc:
        print(f"Gmail fetch failed: {exc}")
        return 2

    print(
        "Gmail fetch complete. "
        f"Messages seen: {gmail_stats.messages_seen}, new messages: {gmail_stats.messages_new}, "
        f"attachments saved: {gmail_stats.attachments_saved}, duplicate attachments skipped: {gmail_stats.attachments_duplicate}."
    )
    for err in gmail_stats.errors or []:
        print(f"Warning: {err}")

    ingest_stats = ingest_from_watched_folder(
        conn=conn,
        watched_input_dirs=cfg.watched_input_dirs,
        extracted_xml_dir=cfg.extracted_xml_dir,
    )

    print(
        "Ingest complete. "
        f"New compressed files: {ingest_stats.zip_files_new}, "
        f"duplicate compressed files skipped: {ingest_stats.zip_files_duplicate}, "
        f"new XML files: {ingest_stats.xml_files_new}, "
        f"duplicate XML files skipped: {ingest_stats.xml_files_duplicate}, "
        f"records inserted: {ingest_stats.records_inserted}."
    )
    for err in ingest_stats.errors or []:
        print(f"Warning: {err}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
