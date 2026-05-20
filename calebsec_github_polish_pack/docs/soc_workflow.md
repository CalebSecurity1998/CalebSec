# SOC Alert Triage Workflow

This document explains the SOC triage process used inside CalebSec.

## 1. Alert Review

The analyst begins by reviewing new alerts in the SOC triage dashboard.

Each alert includes:

- Alert title
- Severity
- Source IP
- Destination IP
- Username or host
- IOC value
- MITRE ATT&CK technique
- Risk score
- Description
- Enrichment summary

## 2. Initial Prioritization

Alerts are prioritized by severity:

- Critical
- High
- Medium
- Low

Critical and High alerts should be reviewed first.

## 3. Investigation

The analyst reviews:

- Source and destination information
- IOC enrichment details
- MITRE ATT&CK mapping
- Alert description
- Related logs or cases

## 4. Status Assignment

The analyst updates the alert status:

- New
- Investigating
- Escalated
- Resolved
- False Positive

## 5. Analyst Notes

The analyst documents findings such as:

- Why the alert is suspicious
- What indicators were observed
- Whether the activity is benign or malicious
- Whether escalation is required
- What remediation steps are recommended

## 6. Resolution

The alert is closed after the analyst determines the outcome.

Possible outcomes:

- Confirmed suspicious activity
- Escalated for further review
- Resolved after investigation
- Marked as false positive

## Example Investigation Note

Multiple failed login attempts were observed from an external IP address against the admin account. The alert was mapped to MITRE ATT&CK T1110 - Brute Force. The source IP should be reviewed for additional activity and blocked if confirmed malicious.
