from __future__ import annotations


def classify_risk(
    disposition: str,
    dkim_result: str,
    spf_result: str,
    reverse_dns: str,
    message_count: int,
) -> tuple[str, int]:
    """Assign a simple explainable risk score for first-pass daily review."""
    score = 0
    disposition = (disposition or "none").lower()
    dkim_result = (dkim_result or "none").lower()
    spf_result = (spf_result or "none").lower()
    reverse_dns = (reverse_dns or "").lower()

    if disposition == "reject":
        score += 45
    elif disposition == "quarantine":
        score += 35
    elif disposition == "none":
        score += 10

    if dkim_result != "pass":
        score += 20
    if spf_result == "softfail":
        score += 20
    elif spf_result != "pass":
        score += 15

    if not reverse_dns:
        score += 10
    if message_count >= 100:
        score += 10

    if score >= 70:
        return "likely spoofing or abuse", score
    if score >= 45:
        return "likely suspicious", score
    if score >= 25:
        return "possible legitimate but unusual", score
    return "likely legitimate", score
