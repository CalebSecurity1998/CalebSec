# README Sections to Add

## Why This Matters

CalebSec was built to simulate real-world SOC analyst workflows, including alert triage, IOC enrichment, phishing analysis, MITRE ATT&CK mapping, and case-style investigation tracking. The goal is to demonstrate practical blue-team skills beyond certification knowledge by showing how security events can be reviewed, enriched, prioritized, and documented.

## Architecture

```text
Browser UI → FastAPI Backend → Detection Logic / SOC Triage / Threat Intel → SQLite Database
```

See `docs/architecture_diagram.md` for the full architecture diagram.

## Screenshots

```markdown
## Dashboard Overview
![Dashboard Overview](screenshots/calebsec-dashboard-overview.png)

## Admin Login
![Admin Login](screenshots/calebsec-admin-login.png)

## Alert Investigation
![Alert Investigation](screenshots/calebsec-alert-investigation.png)

## MITRE ATT&CK Training
![MITRE Training](screenshots/calebsec-mitre-training.png)

## Audit Trail / Analyst Workflow
![Audit Trail](screenshots/1235431a-8ed9-42ad-b6bb-991966fcfa3d.png)
```

## Detection Rules

CalebSec includes detection rules for brute force activity, suspicious PowerShell execution, potential malware beaconing, credential harvesting domains, impossible travel logins, and credential dumping indicators.
