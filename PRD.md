# Product Requirements Document

## Product name
DMARC Daily Review Dashboard

## Overview
This product will help a user review Google DMARC aggregate reports in a lightweight, repeatable daily workflow. The user wants a simple process where Gmail saves zip files into a working directory, the tool automatically unzips and ingests the XML data, and the dashboard surfaces suspicious senders, pass/fail trends, and likely malicious IPs.

The system should be optimized for a daily review workflow, not a high-scale enterprise platform. It should remain lightweight, locally hosted, and easy to maintain.

## Problem
Google DMARC reports are valuable but difficult to review in raw XML form. The report files are repetitive, contain many IP-level records, and are hard to interpret without conversion, summarization, and some form of risk labeling. The current workflow requires manual reading of XML files and manual comparison across reports.

The user needs a simple tool that:
- watches a working directory for new DMARC zip files
- unzips the files automatically
- parses the XML data into structured records
- visualizes daily trends
- highlights suspicious sending patterns
- shows reverse DNS and likely disposition for IP addresses

## Goals
1. Reduce time needed to review DMARC reports manually.
2. Create a daily recurring workflow that starts with a zipped file saved in a working directory.
3. Surface suspicious traffic quickly without requiring deep DMARC expertise.
4. Provide a human review dashboard that is easy to scan in under a few minutes.
5. Keep the stack lightweight, free, and local-first.

## Non-goals
- Full email security platform or SIEM replacement
- Real-time streaming ingestion
- Full abuse investigation workflow
- Bulk enterprise multi-tenant support
- External cloud dependency for core features

## Users
Primary user:
- Security-minded operator managing DMARC for one or more domains

Secondary user:
- Marketing or IT operations owner who wants daily visibility without reading XML

## Core user scenario
A user receives DMARC zip files from Gmail in a folder such as:

- /Users/<user>/Downloads/dmarc/

The user opens the local dashboard, and the tool:
1. scans the folder for new files
2. unzips any archives
3. ingests all XML reports
4. normalizes records into daily tables
5. calculates pass/fail counts and suspicious IP flags
6. displays a summary dashboard and raw record tables

## Functional requirements

### 1. Input ingestion
- The app shall monitor a designated working directory for new DMARC zip files.
- The app shall support zip files saved directly by Gmail or other mail providers.
- The app shall extract XML files from zip archives into a staging directory.
- The app shall avoid re-processing files that have already been ingested.
- The app shall support manual re-ingestion when needed.

### 2. XML parsing
- The app shall parse Google DMARC XML aggregate reports.
- It shall extract at minimum:
  - report date
  - org name
  - domain
  - source IP
  - count
  - disposition
  - DKIM result
  - SPF result
  - header_from
  - auth results
- The app shall normalize all values into consistent columns for analysis.

### 3. Data storage
- The app shall store parsed report data in a local SQLite database or flat-file table.
- The app shall persist daily records for historical comparison.
- The app shall support easy filtering by domain and date.

### 4. Daily overview dashboard
- The app shall show a daily summary of:
  - total messages seen
  - pass count
  - fail count
  - softfail count
  - domain summary
- The app shall show a trend chart for recent days.
- The app shall show a table of suspicious source IPs.

### 5. IP intelligence
- For each source IP, the app shall attempt reverse DNS lookup.
- The app shall display the DNS name alongside the IP.
- The app shall provide a quick heuristic risk classification such as:
  - likely legitimate
  - possible legitimate but unusual
  - likely suspicious
  - likely spoofing or abuse
- The risk logic shall be based on factors such as:
  - known sender patterns
  - repeated softfail traffic
  - multiple unique IPs with identical behavior
  - absence of DKIM/SPF
  - cloud hosting or suspicious reputation indicators

### 6. Visual review workflow
- The app shall provide a dashboard page for a daily review.
- The app shall allow the user to sort by:
  - domain
  - source IP
  - failed counts
  - pass count
  - reverse DNS name
- The app shall show the most suspicious IPs first.
- The app shall maintain an easy raw record view for manual verification.

### 7. Manual actions
- The app shall allow the user to mark an IP as approved or ignored.
- The app shall allow the user to keep notes about a suspicious source.
- The app shall allow exporting a filtered CSV or markdown summary.

### 8. Optional alerting
- The app shall support a lightweight alert threshold feature such as:
  - if fail counts spike over a baseline threshold
  - if a domain sees a sudden increase in softfail IPs
- This can be optional in the first version.

## Non-functional requirements
- The app must be lightweight enough to run on a standard laptop.
- It should require only a few Python dependencies.
- It should run locally without a database server.
- It should be easy to install and launch from a fresh workspace.
- It should be resilient to invalid XML or partially corrupted zip files.
- It should have clear error messages for import failures.

## UX requirements
- The first screen should summarize the current day in under 10 seconds.
- The interface should be readable on a laptop screen with no need for a custom browser setup.
- The dashboard should prioritize suspicious findings and not bury them in raw XML.
- The tool should be understandable by an operator without DMARC expertise.

## Risk and heuristics
The tool should not claim a definitive malicious classification based only on IP reputation. It should present a quick assessment such as:
- likely legitimate
- suspicious
- needs manual review

This supports a human review process rather than acting as a sole decision-maker.

## Proposed architecture
### Components
- Input directory for Gmail DMARC zip files
- Zip extraction utility
- XML parser for DMARC feedback schema
- Local SQLite database
- Streamlit dashboard frontend
- Reverse DNS lookup service using Python socket resolution
- Optional reputation / risk scoring layer

### Suggested tech stack
- Python 3.11+
- Streamlit
- pandas
- sqlite3
- zipfile
- xml.etree.ElementTree
- dnspython (optional for DNS lookups)
- requests or aiohttp for optional external reputation checks (optional)

## Suggested workflow
1. Save Gmail DMARC zip files into a working folder.
2. Launch the Streamlit dashboard.
3. The app auto-discovers new zip files.
4. It extracts XML and parses results.
5. It stores the data in SQLite.
6. It groups records by domain and source IP.
7. It displays a daily summary and suspicious-IP table.
8. The user reviews the suspicious findings and exports a summary if needed.

## Acceptance criteria
1. The app can ingest at least one Gmail DMARC zip file with no manual XML editing.
2. The app extracts and parses report data without errors.
3. The app shows totals by domain and date.
4. The app identifies likely suspicious source IPs using a simple heuristic.
5. The app displays reverse DNS names for raw IPs.
6. The app can be run locally from a clean workspace in a few minutes.
7. The app is easy enough for a daily operator workflow.

## Future enhancements
- Add scheduled poller for a watched directory
- Add email alerts when suspicious counts spike
- Add domain allowlist and ignore list
- Add CSV export and PDF summary
- Add historical comparison against previous 7-30 days
- Add WHOIS / abuse contact lookup for suspicious IPs
- Add domain-specific policy status tracking

## Success metric
The product is successful if a user can open the dashboard, ingest a fresh DMARC archive, and identify suspicious traffic in under 10 minutes without reading raw XML files.

---

## Recommended next step
Create a minimal version 1 scoped to local ingestion, parsing, reverse DNS display, and suspicious-IP scoring. Keep the first release simple. Do not build a giant platform yet.

The first usable version should answer three questions daily:
1. What domains are sending mail today?
2. Which IPs are failing or softfailing?
3. Which IPs look suspicious enough to investigate?
