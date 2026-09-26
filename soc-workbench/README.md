# SentinelAI SOC Workbench

A defensive log investigation workbench for Vikas Dixit's SentinelAI portfolio. It parses JSON, JSONL, CSV, SSH auth logs, and common web access logs; correlates authentication, port sweep, web probing, suspicious command, and large transfer patterns; shows evidence and a timeline; and exports Markdown or JSON reports.

## Deployed app

The owner-private app runs at https://sentinelai-soc-vikas.dixitvikas057.chatgpt.site. It opens with a safe sample investigation. Use **Upload file** or **Paste logs** for your own data. Supported input is up to 2 MB and 5,000 events. Local rule-based triage works without an API key.

The optional **Ask external AI** action sends up to 20 findings and 40 prioritized event excerpts to OpenAI's Responses API for a cautious analyst brief. The key is read only by the server from `OPENAI_API_KEY`; it is never embedded in browser code. This feature becomes available only when that secret is configured for the deployed Site. OpenAI Platform API billing is separate from ChatGPT Plus. The API request uses `gpt-5.6-luna`, `store: false`, a strict JSON schema, and a 25-second timeout. AI output is a hypothesis and cites only event IDs supplied in the request.

## Local rule engine

Serve the standalone `dist/` folder with any HTTP server:

```bash
python3 -m http.server 8080 -d dist
```

Open `http://localhost:8080`. This mode runs local triage and exports; the optional AI button reports that the server route is unavailable. Run tests with `node --test tests/*.test.mjs` (Node 20+). The `site/` folder contains the server-side AI route and client used for the deployed version.

## Input fields

Normalized event fields include `timestamp`, `event_type`, `source_ip`, `destination_ip`, `username`, `destination_port`, `process_name`, `bytes_sent`, `method`, `path`, and `status`. `event_type: "login"` uses `success: true/false`; common authentication failure and success names are also recognized. JSON Windows Security events with `EventID` 4624/4625, `TimeCreated`, `IpAddress`, and `TargetUserName` are mapped to login success/failure. CSV columns may appear in any order but need a time and event type column. Text logs are parsed with limited SSH and access-log patterns, including IPv6 source addresses. Unknown lines remain visible as `other` events and their count is shown after analysis. Missing or invalid timestamps are displayed as unknown and excluded from time-window correlation. Events without a source IP or username are not grouped into a shared source alert; standalone transfer and process indicators can still match.

## Detection rules

| Rule | Pattern | Notes |
| --- | --- | --- |
| AUTH-001 | 5 failed logins per source in 15 minutes; elevates if a success follows within 30 minutes | Requires account/source validation |
| NET-002 | 8 distinct destination ports from one source in 5 minutes | Approved scanning may match |
| WEB-003 | 5 web errors or suspicious paths in 10 minutes | Review application context |
| DATA-004 | At least 50 MB in one outbound event | Size alone is weak evidence |
| PROC-005 | Selected encoded PowerShell or download-and-execute command patterns | Capture process tree before response |

The rule engine runs in the browser. Timeline and finding lists load in pages for larger investigations, while exports include the full result. Files are not uploaded during local triage. Clicking **Ask external AI** explicitly transmits selected evidence excerpts to OpenAI; remove sensitive data first. The deployed Site is private to its owner. Exported reports can contain excerpts of supplied logs, so handle them as sensitive investigation data. No live endpoint actions or SIEM ingestion are performed. Findings are leads, not proof of compromise.

The overall risk score is a triage heuristic. It adds a bounded contribution per detection rule, so a long run of the same rule cannot alone reach a critical score. Validate severity and confidence against the underlying evidence.
