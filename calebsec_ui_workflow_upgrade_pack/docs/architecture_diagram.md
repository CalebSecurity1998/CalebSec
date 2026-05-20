# CalebSec Architecture Diagram

```text
                        ┌──────────────────────────┐
                        │        Web Browser        │
                        │   Analyst Dashboard UI    │
                        └─────────────┬────────────┘
                                      │
                                      ▼
                        ┌──────────────────────────┐
                        │        FastAPI App        │
                        │  Routes + Security Logic  │
                        └─────────────┬────────────┘
                                      │
        ┌─────────────────────────────┼─────────────────────────────┐
        ▼                             ▼                             ▼
┌─────────────────┐         ┌──────────────────┐          ┌──────────────────┐
│ SIEM Dashboard  │         │ SOC Triage       │          │ Threat Intel     │
│ Logs + Alerts   │         │ Cases + Notes    │          │ IOC Enrichment   │
└───────┬─────────┘         └────────┬─────────┘          └────────┬─────────┘
        │                            │                             │
        ▼                            ▼                             ▼
┌─────────────────┐         ┌──────────────────┐          ┌──────────────────┐
│ Detection Logic │         │ Analyst Activity │          │ MITRE Mapping    │
│ Alert Rules     │         │ Workflow Events  │          │ Risk Scoring     │
└───────┬─────────┘         └────────┬─────────┘          └────────┬─────────┘
        │                            │                             │
        └─────────────────────────────┼─────────────────────────────┘
                                      ▼
                        ┌──────────────────────────┐
                        │        SQLite DB         │
                        │ Logs, Alerts, Cases, IOC │
                        └──────────────────────────┘
```

## Architecture Summary

CalebSec uses a FastAPI backend with SQLite storage and Jinja2 templates. The platform separates SOC workflows into modules for SIEM monitoring, alert triage, threat intelligence, detection rules, and analyst activity tracking.
