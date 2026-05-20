# Detection Rules

CalebSec includes detection rules for common SOC investigation scenarios.

## Current Rules

| Rule | Severity | MITRE Technique | Purpose |
|---|---|---|---|
| Brute Force to Successful Login | Critical | T1110 | Detect repeated failed logins followed by success |
| Suspicious PowerShell Execution | Critical | T1059.001 | Detect encoded or hidden PowerShell behavior |
| Potential Malware Beaconing | High | T1071 | Detect repeated outbound communication |
| Credential Harvesting Domain | High | T1566 | Detect phishing-themed domains |
| Impossible Travel Login | Medium | T1078 | Detect unusual successful login behavior |
| Potential Credential Dumping | Critical | T1003 | Detect credential dumping indicators |

## Analyst Value

These rules demonstrate practical detection engineering concepts and map security activity to real MITRE ATT&CK techniques.
