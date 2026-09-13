from __future__ import annotations

import bz2
import gzip
import hashlib
import io
import lzma
import tarfile
import zipfile
from dataclasses import dataclass
from pathlib import Path

from dmarc_review import db
from dmarc_review.parser import parse_dmarc_xml
from dmarc_review.risk import classify_risk


@dataclass
class IngestStats:
    zip_files_seen: int = 0
    zip_files_new: int = 0
    zip_files_duplicate: int = 0
    xml_files_new: int = 0
    xml_files_duplicate: int = 0
    records_inserted: int = 0
    errors: list[str] | None = None

    def __post_init__(self) -> None:
        if self.errors is None:
            self.errors = []


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _stable_extracted_name(zip_name: str, xml_name: str, xml_hash: str) -> str:
    zip_stem = Path(zip_name).stem
    xml_stem = Path(xml_name).stem
    return f"{zip_stem}__{xml_stem}__{xml_hash[:12]}.xml"


def _looks_like_xml(payload: bytes) -> bool:
    trimmed = payload.lstrip()
    return trimmed.startswith(b"<?xml") or trimmed.startswith(b"<feedback")


def _xml_name_from_archive_name(archive_name: str) -> str:
    stem = Path(archive_name).stem
    if stem.lower().endswith(".xml"):
        return stem
    return f"{stem}.xml"


def _extract_xml_bytes_from_tar_payload(payload: bytes) -> list[tuple[str, bytes]]:
    extracted: list[tuple[str, bytes]] = []
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:*") as tf:
        for member in tf.getmembers():
            if not member.isfile():
                continue

            member_name = Path(member.name).name
            data_file = tf.extractfile(member)
            if data_file is None:
                continue

            member_bytes = data_file.read()
            if member_name.lower().endswith(".xml") or _looks_like_xml(member_bytes):
                xml_name = member_name if member_name.lower().endswith(".xml") else f"{Path(member_name).stem}.xml"
                extracted.append((xml_name, member_bytes))
    return extracted


def _is_tar_payload(payload: bytes) -> bool:
    try:
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:*"):
            return True
    except tarfile.TarError:
        return False


def _extract_xml_payloads(archive_path: Path, archive_bytes: bytes) -> list[tuple[str, bytes]]:
    extracted: list[tuple[str, bytes]] = []

    if zipfile.is_zipfile(io.BytesIO(archive_bytes)):
        with zipfile.ZipFile(io.BytesIO(archive_bytes), "r") as zf:
            for member in zf.infolist():
                if member.is_dir():
                    continue

                member_name = Path(member.filename).name
                with zf.open(member, "r") as src:
                    member_bytes = src.read()

                if member_name.lower().endswith(".xml") or _looks_like_xml(member_bytes):
                    xml_name = member_name if member_name.lower().endswith(".xml") else f"{Path(member_name).stem}.xml"
                    extracted.append((xml_name, member_bytes))
        return extracted

    if _is_tar_payload(archive_bytes):
        return _extract_xml_bytes_from_tar_payload(archive_bytes)

    decompressor_errors: list[Exception] = []
    for decompressor in (gzip.decompress, bz2.decompress, lzma.decompress):
        try:
            uncompressed = decompressor(archive_bytes)
        except Exception as exc:  # noqa: BLE001 - tried compression did not match
            decompressor_errors.append(exc)
            continue

        if _looks_like_xml(uncompressed):
            return [(_xml_name_from_archive_name(archive_path.name), uncompressed)]
        if _is_tar_payload(uncompressed):
            return _extract_xml_bytes_from_tar_payload(uncompressed)

    if _looks_like_xml(archive_bytes):
        return [(_xml_name_from_archive_name(archive_path.name), archive_bytes)]

    raise ValueError(
        f"Unsupported archive format for {archive_path.name}; expected zip/gzip/bzip2/xz/tar containing XML."
    )


def _persist_extracted_xml(
    archive_name: str,
    xml_name: str,
    xml_bytes: bytes,
    extract_dir: Path,
) -> tuple[Path, str, str]:
    xml_hash = _sha256_bytes(xml_bytes)
    target_name = _stable_extracted_name(archive_name, xml_name, xml_hash)
    target_path = extract_dir / target_name
    if not target_path.exists():
        target_path.write_bytes(xml_bytes)
    return target_path, xml_name, xml_hash


def _list_incoming_files(watched_input_dirs: tuple[Path, ...]) -> list[Path]:
    incoming_files: list[Path] = []
    for watched_dir in watched_input_dirs:
        if not watched_dir.exists():
            continue
        for file_path in watched_dir.iterdir():
            if not file_path.is_file():
                continue
            if file_path.name.startswith("."):
                continue
            incoming_files.append(file_path)
    return sorted(incoming_files)


def ingest_from_watched_folder(
    conn,
    watched_input_dirs: tuple[Path, ...],
    extracted_xml_dir: Path,
) -> IngestStats:
    stats = IngestStats()
    archive_files = _list_incoming_files(watched_input_dirs)
    stats.zip_files_seen = len(archive_files)

    for archive_path in archive_files:
        archive_name = archive_path.name
        source_key = f"archive-source::{archive_path.resolve()}"

        try:
            archive_bytes = archive_path.read_bytes()
            archive_hash = _sha256_bytes(archive_bytes)
        except OSError as exc:
            stats.errors.append(f"Failed to read {archive_name}: {exc}")
            continue

        source_hash_key = f"archive-source-hash::{source_key}::{archive_hash}"
        archive_hash_key = f"archivesha::{archive_hash}"

        if db.has_processed_file(conn, source_hash_key):
            continue

        if db.has_processed_file(conn, archive_hash_key):
            stats.zip_files_duplicate += 1
            db.mark_processed_file(conn, source_hash_key, "archive-source-hash-alias")
            continue

        stats.zip_files_new += 1

        try:
            xml_payloads = _extract_xml_payloads(archive_path, archive_bytes)
            extracted_entries = [
                _persist_extracted_xml(archive_name, xml_name, xml_bytes, extracted_xml_dir)
                for xml_name, xml_bytes in xml_payloads
            ]
            db.mark_processed_file(conn, source_hash_key, "archive-source-hash")
            db.mark_processed_file(conn, archive_hash_key, "archive-hash")
        except (zipfile.BadZipFile, tarfile.TarError, ValueError) as exc:
            stats.errors.append(f"Failed to extract {archive_name}: {exc}")
            continue
        except OSError as exc:
            stats.errors.append(f"Failed to extract {archive_name}: {exc}")
            continue

        for xml_path, original_xml_name, xml_hash in extracted_entries:
            tagged_xml_name = f"{archive_name}::{original_xml_name}"
            xml_hash_key = f"xmlsha::{xml_hash}"
            if db.has_processed_file(conn, tagged_xml_name):
                continue
            if db.has_processed_file(conn, xml_hash_key):
                stats.xml_files_duplicate += 1
                db.mark_processed_file(conn, tagged_xml_name, "xml-alias")
                continue

            try:
                xml_text = xml_path.read_text(encoding="utf-8", errors="ignore")
                rows = parse_dmarc_xml(xml_text)

                enriched_rows: list[dict] = []
                for row in rows:
                    label, score = classify_risk(
                        row.get("disposition", "none"),
                        row.get("dkim_result", "none"),
                        row.get("spf_result", "none"),
                        row.get("reverse_dns", ""),
                        int(row.get("message_count", 0)),
                    )
                    row["risk_label"] = label
                    row["risk_score"] = score
                    row["xml_file_name"] = original_xml_name
                    row["zip_file_name"] = archive_name
                    enriched_rows.append(row)

                inserted = db.insert_records(conn, enriched_rows)
                stats.records_inserted += inserted
                stats.xml_files_new += 1
                db.mark_processed_file(conn, tagged_xml_name, "xml")
                db.mark_processed_file(conn, xml_hash_key, "xml-hash")
            except Exception as exc:  # nosec - show parse errors in UI for operator review
                stats.errors.append(f"Failed to parse {original_xml_name}: {exc}")

    return stats
