# SentinelAI SOC Workbench

A defensive investigation workbench built for Vikas Dixit's SentinelAI portfolio. It parses JSON, JSONL, CSV, SSH auth logs, and common web access logs; correlates authentication, port sweep, web probing, suspicious command, and large transfer patterns; presents a timeline and evidence; and exports Markdown or JSON investigation reports.

## Run locally

The `dist/` directory is a static application. Serve it with any local HTTP server:

```bash
python3 -m http.server 8080 -d dist
```

Open `http://localhost:8080`. It opens with a safe sample investigation. Use **Upload file** or **Paste logs** for your own data. Supported input is up to 2 MB and 5,000 events. Run the focused detection tests with `node --test tests/*.test.mjs` (Node 20+).

## Input fields

Normalized event fields include `timestamp`, `event_type`, `source_ip`, `destination_ip`, `username`, `destination_port`, `process_name`, `bytes_sent`, `method`, `path`, and `status`. `event_type: "login"` uses `success: true/false`. Text logs are parsed with limited SSH and access-log patterns. Unknown lines remain visible as `other` events.

## Detection rules

| Rule | Pattern | Notes |
| --- | --- | --- |
| AUTH-001 | 5 failed logins per source in 15 minutes; elevates if a success follows within 30 minutes | Requires account/source validation |
| NET-002 | 8 distinct destination ports from one source in 5 minutes | Approved scanning may match |
| WEB-003 | 5 web errors or suspicious paths in 10 minutes | Review application context |
| DATA-004 | At least 50 MB in one outbound event | Size alone is weak evidence |
| PROC-005 | Selected encoded PowerShell or download-and-execute command patterns | Capture process tree before response |

The engine runs in the browser. Files are read locally and are not uploaded to an AI provider or stored on a server. The deployed site is private to its owner. Exported reports contain excerpts of supplied logs, so handle them as sensitive investigation data. Findings are leads, not proof of compromise. No live endpoint actions are taken.

## Architecture

`index.html` renders the triage workspace, `app.mjs` handles file input and visualization, and `detector.mjs` contains pure parsing, correlation, and report functions. This workbench complements the FastAPI event scoring service in the root of the SentinelAI repository; it does not claim to be connected to a running backend.
