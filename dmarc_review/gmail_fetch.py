from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from pathlib import Path

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

from dmarc_review import db

GMAIL_SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]
ACCEPTED_EXTENSIONS = {
    ".zip",
    ".gz",
    ".gx",
    ".tgz",
    ".tar",
    ".bz2",
    ".xz",
    ".xml",
}


class GmailFetchError(Exception):
    """Raised when Gmail fetch setup or API calls cannot proceed."""


@dataclass
class GmailFetchStats:
    messages_seen: int = 0
    messages_new: int = 0
    attachments_saved: int = 0
    attachments_duplicate: int = 0
    errors: list[str] | None = None

    def __post_init__(self) -> None:
        if self.errors is None:
            self.errors = []


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _safe_name(file_name: str) -> str:
    candidate = Path(file_name).name.strip().replace(" ", "_")
    if not candidate:
        return "attachment.bin"
    return candidate


def _is_candidate_dmarc_attachment(file_name: str) -> bool:
    lowered = file_name.lower()
    if any(lowered.endswith(ext) for ext in ACCEPTED_EXTENSIONS):
        return True
    return "dmarc" in lowered or "rua" in lowered


def _decode_attachment_bytes(encoded_data: str) -> bytes:
    return base64.urlsafe_b64decode(encoded_data.encode("utf-8"))


def _load_credentials(credentials_path: Path, token_path: Path) -> Credentials:
    creds: Credentials | None = None
    if token_path.exists():
        creds = Credentials.from_authorized_user_file(str(token_path), GMAIL_SCOPES)

    if creds and creds.valid:
        return creds

    if creds and creds.expired and creds.refresh_token:
        creds.refresh(Request())
        token_path.write_text(creds.to_json(), encoding="utf-8")
        return creds

    if not credentials_path.exists():
        raise GmailFetchError(
            f"Missing Gmail OAuth client file: {credentials_path}. "
            "Create an OAuth Desktop App client in Google Cloud and save the JSON there."
        )

    flow = InstalledAppFlow.from_client_secrets_file(str(credentials_path), GMAIL_SCOPES)
    creds = flow.run_local_server(port=0)
    token_path.write_text(creds.to_json(), encoding="utf-8")
    return creds


def _iter_message_parts(payload: dict) -> list[dict]:
    parts = []
    stack = [payload]
    while stack:
        part = stack.pop()
        parts.append(part)
        stack.extend(part.get("parts", []))
    return parts


def fetch_gmail_dmarc_attachments(
    conn,
    incoming_dir: Path,
    credentials_path: Path,
    token_path: Path,
    query: str,
    max_results: int = 100,
) -> GmailFetchStats:
    stats = GmailFetchStats()

    try:
        creds = _load_credentials(credentials_path, token_path)
    except Exception as exc:  # noqa: BLE001 - expose setup issues to user
        raise GmailFetchError(str(exc)) from exc

    service = build("gmail", "v1", credentials=creds, cache_discovery=False)

    next_page_token: str | None = None
    while True:
        response = (
            service.users()
            .messages()
            .list(userId="me", q=query, maxResults=max_results, pageToken=next_page_token)
            .execute()
        )

        messages = response.get("messages", [])
        for msg in messages:
            message_id = msg.get("id", "")
            if not message_id:
                continue

            stats.messages_seen += 1
            message_key = f"gmail-message::{message_id}"
            if db.has_processed_file(conn, message_key):
                continue

            stats.messages_new += 1

            try:
                full_message = (
                    service.users()
                    .messages()
                    .get(userId="me", id=message_id, format="full")
                    .execute()
                )

                payload = full_message.get("payload", {})
                for part in _iter_message_parts(payload):
                    file_name = part.get("filename", "")
                    body = part.get("body", {})
                    if not file_name or not _is_candidate_dmarc_attachment(file_name):
                        continue

                    attachment_id = body.get("attachmentId")
                    if attachment_id:
                        attachment = (
                            service.users()
                            .messages()
                            .attachments()
                            .get(userId="me", messageId=message_id, id=attachment_id)
                            .execute()
                        )
                        encoded_data = attachment.get("data", "")
                    else:
                        encoded_data = body.get("data", "")

                    if not encoded_data:
                        continue

                    attachment_bytes = _decode_attachment_bytes(encoded_data)
                    attachment_hash = _sha256_bytes(attachment_bytes)
                    attachment_key = f"gmail-attachment::{attachment_hash}"
                    if db.has_processed_file(conn, attachment_key):
                        stats.attachments_duplicate += 1
                        continue

                    safe_name = _safe_name(file_name)
                    file_path = incoming_dir / f"{Path(safe_name).stem}__{attachment_hash[:12]}{Path(safe_name).suffix}"
                    file_path.write_bytes(attachment_bytes)
                    db.mark_processed_file(conn, attachment_key, "gmail-attachment-hash")
                    stats.attachments_saved += 1

                db.mark_processed_file(conn, message_key, "gmail-message")
            except Exception as exc:  # noqa: BLE001 - keep fetching other messages
                stats.errors.append(f"Failed to process Gmail message {message_id}: {exc}")

        next_page_token = response.get("nextPageToken")
        if not next_page_token:
            break

    return stats
