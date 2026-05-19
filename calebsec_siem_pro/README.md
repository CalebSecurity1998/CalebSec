# CalebSec SIEM Console Pro

A portfolio-friendly Python/FastAPI SIEM console for SOC analyst and blue-team job training.

## Added Pro Features

- Modular detection engine with MITRE ATT&CK metadata
- Brute force, after-hours login, PowerShell abuse, privilege escalation, IOC match, impossible travel, and beaconing detections
- IOC enrichment from `threat_intel/iocs.json`
- Advanced attack scenario ingestion
- Simulated live attack feed generator
- MITRE ATT&CK tactic heatmap on the dashboard
- SOC Analyst Training Mode section
- `/api/summary` endpoint for dashboard/API demos
- Dockerfile and docker-compose support
- GitHub Actions CI workflow
- Pytest detection test

## Run Locally

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload
```

Open: http://127.0.0.1:8000

Default login uses environment variables. For local testing, defaults are:

- Username: `caleb`
- Password: `change-this-password`

Change these before deploying.

## Run with Docker

```bash
docker compose up --build
```

## Suggested Resume Line

Developed a Python/FastAPI SIEM platform with MITRE ATT&CK mapped detections, IOC enrichment, alert/case workflows, audit logging, simulated attack ingestion, and Docker-based deployment support.
