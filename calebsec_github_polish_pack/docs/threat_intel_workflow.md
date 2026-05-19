# Threat Intelligence Workflow

This document explains how CalebSec performs IOC enrichment and threat intelligence scoring.

## Supported IOC Types

CalebSec supports local analysis of:

- IP addresses
- Domains
- URLs
- Hashes
- Suspicious command strings

## IOC Lookup Process

1. Analyst enters an IOC.
2. CalebSec determines or receives the IOC type.
3. The IOC is analyzed using local scoring logic.
4. A risk score is generated.
5. A verdict is assigned.
6. A MITRE ATT&CK mapping is added.
7. The lookup is saved in IOC history.

## Risk Scores

Risk scores range from 0 to 100.

Example verdict levels:

- 0–19: Low Risk
- 20–44: Needs Review
- 45–74: Suspicious
- 75–100: High Risk

## Example Indicators

A domain may be scored higher if it:

- Uses a suspicious top-level domain
- Contains phishing-related keywords
- Appears randomly generated
- Uses unencrypted HTTP

An IP may be scored higher if it:

- Is public
- Matches a known suspicious range
- Appears in alert context

A command may be scored higher if it contains:

- PowerShell
- EncodedCommand
- certutil
- rundll32
- regsvr32
- credential dumping keywords

## MITRE ATT&CK Examples

- Phishing domains: T1566 – Phishing
- Suspicious PowerShell: T1059.001 – PowerShell
- External C2-like IP communication: T1071 – Application Layer Protocol
- File hash indicators: T1204 – User Execution
