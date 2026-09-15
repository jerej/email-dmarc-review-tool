# DMARC Daily Review Dashboard

Local-first prototype for daily DMARC aggregate report review.

## Dependency management

This repo now uses Poetry as the primary environment and dependency manager.

## Current prototype scope

- Python scaffold with reusable modules under `dmarc_review/`
- DMARC XML parser for aggregate report records
- Watched folders for incoming compressed DMARC report files
- Gmail API downloader for labeled DMARC attachments
- SQLite persistence for parsed records
- Streamlit dashboard skeleton with:
  - daily metrics
  - trend chart
  - domain summary
  - suspicious IP table
  - raw record table

## Project structure

- `PRD.md` product requirements and workflow
- `app.py` Streamlit app entrypoint
- `dmarc_review/config.py` path and folder setup
- `dmarc_review/ingest.py` compressed report ingestion flow (zip, gz/gx, tar.gz, bz2, xz, xml)
- `dmarc_review/gmail_fetch.py` Gmail label-based attachment fetcher
- `dmarc_review/parser.py` DMARC XML parsing + reverse DNS lookup
- `dmarc_review/risk.py` initial risk scoring heuristic
- `dmarc_review/db.py` SQLite schema + query helpers
- `data/compressed_incoming/` watched input directory for compressed reports
- `data/extracted_xml/` extracted XML staging files
- `.env.example` Gmail fetch configuration template

## Quick start

Requires Python 3.10 or newer for Poetry-managed installs.

1. Install Poetry (one-time):

```bash
pipx install poetry
```

1. Install dependencies:

```bash
poetry install
```

1. Optional: copy env template:

```bash
cp .env.example .env
```

1. Launch the dashboard:

```bash
poetry run streamlit run app.py
```

1. Copy incoming DMARC report files into:

```text
data/compressed_incoming/
```

1. In the app, click **Scan Watched Folder Now**.

## Gmail automatic attachment fetch (Option 1)

1. In [Google Cloud Console](https://console.cloud.google.com/welcome), enable the Gmail API.
2. Create OAuth client credentials for a Desktop app.
3. Download the client JSON and save it as `credentials.json` at project root
   (or set `GMAIL_CREDENTIALS_PATH` in `.env`).
4. In Gmail, create a label such as `DMARC-Reports` and a filter that applies
   that label to DMARC aggregate report emails.
5. In the app sidebar, click **Fetch Gmail DMARC Attachments**.
6. On first run, complete OAuth in your browser; token will be cached at
   `data/gmail_token.json`.

The app will:

- fetch labeled Gmail messages with attachments
- save candidate DMARC compressed attachments into `data/compressed_incoming/`
- dedupe by attachment content hash
- mark successfully processed source Gmail messages as read by default
- auto-run ingestion when new attachments are saved

To keep messages unread instead, set `GMAIL_MARK_AS_READ=false` in `.env`.

OAuth scope follows this setting:

- `GMAIL_MARK_AS_READ=true` uses `gmail.modify` (needed to clear `UNREAD`)
- `GMAIL_MARK_AS_READ=false` uses `gmail.readonly`

If you change `GMAIL_MARK_AS_READ` after authenticating, the next fetch may prompt OAuth consent again so the cached token matches the required scope.

If Gmail returns an `invalid_scope` (or similar permission/scope) error, the app now retries auth once by invalidating the cached token and re-running OAuth.
If auth still fails, remove the token cache manually and retry:

```bash
rm -f data/gmail_token.json
```

Then click **Fetch Gmail DMARC Attachments** again to force a fresh login.

## Unattended automation

You can run Gmail fetch + ingestion without opening Streamlit:

```bash
poetry run dmarc-fetch
```

Example cron entry (daily at 6:15 AM):

```cron
15 6 * * * cd /Users/yourname/src/dmarc-review-tool && /usr/bin/env poetry run dmarc-fetch >> data/fetch.log 2>&1
```

For macOS launchd, use the same command in a LaunchAgent with your preferred interval.

Supported incoming compressed formats include:

- `.zip`
- `.gz` and `.gx` (gzip content)
- `.tar`, `.tar.gz`, `.tgz`
- `.bz2`
- `.xz`
- raw `.xml`

The ingestion process avoids reprocessing already-seen ZIP/XML files.

## Notes

- The parser is defensive against missing fields and supports namespaced XML tags.
- Reverse DNS lookup failures are handled gracefully.
- Risk labels are heuristic and intended for human triage, not automated blocking.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE).
