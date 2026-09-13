from __future__ import annotations

import socket
import xml.etree.ElementTree as ET


def _tag_name(tag: str) -> str:
    if "}" in tag:
        return tag.rsplit("}", 1)[-1]
    return tag


def _find_child(element: ET.Element, child_name: str) -> ET.Element | None:
    for child in list(element):
        if _tag_name(child.tag) == child_name:
            return child
    return None


def _find_text(element: ET.Element | None, child_name: str, default: str = "") -> str:
    if element is None:
        return default
    child = _find_child(element, child_name)
    if child is None or child.text is None:
        return default
    return child.text.strip()


def reverse_dns_lookup(ip: str) -> str:
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        return host
    except (socket.herror, socket.gaierror, OSError):
        return ""


def parse_dmarc_xml(xml_text: str) -> list[dict]:
    root = ET.fromstring(xml_text)

    metadata = _find_child(root, "report_metadata")
    policy = _find_child(root, "policy_published")

    report_id = _find_text(metadata, "report_id")
    org_name = _find_text(metadata, "org_name")
    domain = _find_text(policy, "domain")

    date_range = _find_child(metadata, "date_range")
    report_start = int(_find_text(date_range, "begin", "0") or "0")
    report_end = int(_find_text(date_range, "end", "0") or "0")

    parsed_rows: list[dict] = []
    for record in list(root):
        if _tag_name(record.tag) != "record":
            continue

        row = _find_child(record, "row")
        identifiers = _find_child(record, "identifiers")
        auth_results = _find_child(record, "auth_results")

        source_ip = _find_text(row, "source_ip")
        message_count = int(_find_text(row, "count", "0") or "0")

        policy_eval = _find_child(row, "policy_evaluated")
        disposition = _find_text(policy_eval, "disposition", "none")
        dkim_result = _find_text(policy_eval, "dkim", "none")
        spf_result = _find_text(policy_eval, "spf", "none")

        header_from = _find_text(identifiers, "header_from")

        auth_dkim = _find_child(auth_results, "dkim")
        auth_spf = _find_child(auth_results, "spf")

        reverse_dns = reverse_dns_lookup(source_ip) if source_ip else ""

        parsed_rows.append(
            {
                "report_id": report_id,
                "org_name": org_name,
                "domain": domain,
                "report_start": report_start,
                "report_end": report_end,
                "source_ip": source_ip,
                "message_count": message_count,
                "disposition": disposition,
                "dkim_result": dkim_result,
                "spf_result": spf_result,
                "header_from": header_from,
                "auth_dkim_domain": _find_text(auth_dkim, "domain"),
                "auth_dkim_result": _find_text(auth_dkim, "result"),
                "auth_spf_domain": _find_text(auth_spf, "domain"),
                "auth_spf_result": _find_text(auth_spf, "result"),
                "reverse_dns": reverse_dns,
            }
        )

    return parsed_rows
