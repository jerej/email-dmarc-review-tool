# DMARC Daily Review Dashboard

This workspace contains a product requirements document for a lightweight local tool that reviews Gmail DMARC zip reports.

## Included
- PRD.md — product requirements and workflow definition

## Intended stack
- Python
- Streamlit
- SQLite
- pandas

## Main workflow
1. Save Gmail DMARC zip files in a working directory.
2. The tool unzips the files.
3. It parses the XML aggregate reports.
4. It stores the records locally.
5. It summarizes daily activity and highlights suspicious IPs.

## Recommended next step
Implement a minimal v1 in a fresh project folder using Streamlit and SQLite.
