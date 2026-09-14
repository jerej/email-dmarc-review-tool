from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv


@dataclass(frozen=True)
class AppConfig:
    base_dir: Path
    incoming_compressed_dir: Path
    legacy_gmail_zip_dir: Path
    watched_input_dirs: tuple[Path, ...]
    extracted_xml_dir: Path
    db_path: Path
    gmail_credentials_path: Path
    gmail_token_path: Path
    gmail_label_query: str
    gmail_max_results: int
    gmail_mark_as_read: bool


def load_config() -> AppConfig:
    """Return filesystem paths used by the local prototype."""
    load_dotenv()
    base_dir = Path.cwd()
    data_dir = base_dir / "data"
    incoming_compressed_dir = data_dir / "compressed_incoming"
    legacy_gmail_zip_dir = data_dir / "gmail_zips"
    extracted_xml_dir = data_dir / "extracted_xml"
    db_path = data_dir / "dmarc_reports.sqlite"
    gmail_credentials_path = base_dir / os.getenv("GMAIL_CREDENTIALS_PATH", "credentials.json")
    gmail_token_path = base_dir / os.getenv("GMAIL_TOKEN_PATH", "data/gmail_token.json")
    gmail_label_query = os.getenv("GMAIL_LABEL_QUERY", "label:DMARC-Reports has:attachment")
    gmail_max_results = int(os.getenv("GMAIL_MAX_RESULTS", "100"))
    gmail_mark_as_read = os.getenv("GMAIL_MARK_AS_READ", "true").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }

    incoming_compressed_dir.mkdir(parents=True, exist_ok=True)
    legacy_gmail_zip_dir.mkdir(parents=True, exist_ok=True)
    extracted_xml_dir.mkdir(parents=True, exist_ok=True)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    gmail_token_path.parent.mkdir(parents=True, exist_ok=True)

    return AppConfig(
        base_dir=base_dir,
        incoming_compressed_dir=incoming_compressed_dir,
        legacy_gmail_zip_dir=legacy_gmail_zip_dir,
        watched_input_dirs=(incoming_compressed_dir, legacy_gmail_zip_dir),
        extracted_xml_dir=extracted_xml_dir,
        db_path=db_path,
        gmail_credentials_path=gmail_credentials_path,
        gmail_token_path=gmail_token_path,
        gmail_label_query=gmail_label_query,
        gmail_max_results=gmail_max_results,
        gmail_mark_as_read=gmail_mark_as_read,
    )
