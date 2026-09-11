# SentinelAI 🛡️

SentinelAI is an AI-ready personal SOC (Security Operations Center) project for defensive cybersecurity monitoring.

It receives security events, scores risk, detects suspicious patterns, and returns clear remediation advice through a FastAPI backend.

## Features

- FastAPI REST API
- Risk score from 0–100
- Severity classification
- Brute-force/login anomaly detection
- Sensitive-port detection
- Suspicious-process detection
- Large outbound-transfer detection
- Human-readable recommendations
- Automated tests
- Docker support

## Architecture

```text
Security Event
    |
    v
FastAPI API
    |
    v
Detection Engine
    |
    +--> Rule Checks
    +--> Risk Score
    +--> Severity
    +--> Recommendations
    |
    v
JSON Alert Response
```

## Project structure

```text
SentinelAI/
├── app/
│   ├── __init__.py
│   ├── main.py
│   ├── detector.py
│   └── models.py
├── tests/
│   └── test_api.py
├── requirements.txt
├── Dockerfile
├── .gitignore
└── README.md
```

## Run locally

```bash
python -m venv .venv
```

Windows:

```bash
.venv\Scripts\activate
```

Linux/macOS:

```bash
source .venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Start the API:

```bash
uvicorn app.main:app --reload
```

Open:

```text
http://127.0.0.1:8000/docs
```

## Example request

```json
{
  "event_type": "login",
  "source_ip": "192.168.1.20",
  "username": "admin",
  "success": false,
  "failed_attempts": 12,
  "destination_port": 22,
  "process_name": "powershell.exe",
  "bytes_sent": 65000000,
  "destination_ip": "203.0.113.50"
}
```

## Example response

```json
{
  "risk_score": 100,
  "severity": "critical",
  "alerts": [
    "Possible brute-force login activity",
    "Connection to a sensitive service port",
    "Suspicious process observed",
    "Large outbound data transfer"
  ],
  "recommendations": [
    "Temporarily block the source IP and inspect authentication logs.",
    "Verify whether this service exposure is expected.",
    "Inspect the process command line and parent process.",
    "Review the destination and validate whether the transfer is legitimate."
  ]
}
```

## Roadmap

- SQLite/PostgreSQL event storage
- Live Windows Event Log ingestion
- Linux auth.log ingestion
- Dashboard with attack timeline
- ML anomaly detection
- Threat-intelligence enrichment
- AI analyst explanations
- Authentication and user accounts

## Ethical use

SentinelAI is designed for defensive monitoring, education, and authorized environments only.

## Author

Vikas Dixit
