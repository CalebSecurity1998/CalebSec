ENHANCED_SOC_ALERTS = [
    {
        "title": "Impossible Travel Login",
        "severity": "High",
        "source_ip": "203.0.113.25",
        "destination_ip": "10.0.0.12",
        "username": "finance.user",
        "ioc_value": "203.0.113.25",
        "ioc_type": "ip",
        "mitre_technique": "T1078 - Valid Accounts",
        "description": "A successful login occurred from a geographically unusual source shortly after a normal login from the user's home region.",
        "status": "Investigating",
        "analyst_notes": "Review user sign-in history, MFA status, and recent password reset activity.",
        "assigned_to": "Caleb",
        "risk_score": 72,
        "enrichment_summary": "Public IP observed in suspicious authentication context. Recommend validating with user and reviewing MFA logs."
    },
    {
        "title": "Suspicious PowerShell Download Cradle",
        "severity": "Critical",
        "source_ip": "10.0.0.44",
        "destination_ip": "198.51.100.77",
        "username": "workstation-044",
        "ioc_value": "powershell -nop -w hidden -enc",
        "ioc_type": "command",
        "mitre_technique": "T1059.001 - PowerShell",
        "description": "Encoded PowerShell execution was observed with hidden window behavior, which may indicate script-based payload delivery.",
        "status": "Escalated",
        "analyst_notes": "Isolate host if confirmed. Review endpoint process tree and command-line history.",
        "assigned_to": "Caleb",
        "risk_score": 95,
        "enrichment_summary": "Suspicious command behavior detected: PowerShell, encoded command, hidden execution."
    },
    {
        "title": "Potential Malware Beaconing",
        "severity": "Critical",
        "source_ip": "10.0.0.31",
        "destination_ip": "45.83.64.12",
        "username": "workstation-031",
        "ioc_value": "45.83.64.12",
        "ioc_type": "ip",
        "mitre_technique": "T1071 - Application Layer Protocol",
        "description": "Repeated outbound connections were observed at regular intervals to a suspicious external IP.",
        "status": "New",
        "analyst_notes": "",
        "assigned_to": "",
        "risk_score": 91,
        "enrichment_summary": "Repeated outbound traffic pattern is consistent with potential C2 beaconing."
    },
    {
        "title": "Credential Harvesting Domain Detected",
        "severity": "High",
        "source_ip": "10.0.0.18",
        "destination_ip": "192.0.2.55",
        "username": "user01",
        "ioc_value": "secure-login-verification.example.com",
        "ioc_type": "domain",
        "mitre_technique": "T1566 - Phishing",
        "description": "User-submitted email contained a suspicious login-themed domain commonly associated with phishing attempts.",
        "status": "Investigating",
        "analyst_notes": "Check whether user submitted credentials. Search mail logs for additional recipients.",
        "assigned_to": "Caleb",
        "risk_score": 83,
        "enrichment_summary": "Domain contains credential-harvesting keywords: secure, login, verification."
    },
    {
        "title": "Possible Credential Dumping Tool Execution",
        "severity": "Critical",
        "source_ip": "10.0.0.52",
        "destination_ip": "10.0.0.10",
        "username": "admin",
        "ioc_value": "mimikatz",
        "ioc_type": "command",
        "mitre_technique": "T1003 - OS Credential Dumping",
        "description": "Suspicious credential dumping keyword detected in command execution telemetry.",
        "status": "Escalated",
        "analyst_notes": "Immediate endpoint containment recommended. Rotate potentially exposed credentials.",
        "assigned_to": "Caleb",
        "risk_score": 98,
        "enrichment_summary": "Credential dumping behavior indicator detected. High confidence security event."
    }
]

DETECTION_RULES = [
    {
        "rule_name": "Brute Force to Successful Login",
        "severity": "Critical",
        "mitre_technique": "T1110 - Brute Force",
        "detection_logic": "Five or more failed login attempts followed by a successful login from the same source IP.",
        "description": "Identifies possible credential brute forcing followed by successful account access."
    },
    {
        "rule_name": "Suspicious PowerShell Execution",
        "severity": "Critical",
        "mitre_technique": "T1059.001 - PowerShell",
        "detection_logic": "Detect command strings containing PowerShell plus encoded or hidden execution flags.",
        "description": "Identifies script-based execution commonly used for payload delivery or defense evasion."
    },
    {
        "rule_name": "Potential Malware Beaconing",
        "severity": "High",
        "mitre_technique": "T1071 - Application Layer Protocol",
        "detection_logic": "Repeated outbound connections to the same external IP/domain at regular intervals.",
        "description": "Detects possible command-and-control traffic patterns."
    },
    {
        "rule_name": "Credential Harvesting Domain",
        "severity": "High",
        "mitre_technique": "T1566 - Phishing",
        "detection_logic": "Domain or URL contains login, verify, password, secure, MFA, account, or reset keywords.",
        "description": "Flags phishing-themed domains that may be used for credential theft."
    },
    {
        "rule_name": "Impossible Travel Login",
        "severity": "Medium",
        "mitre_technique": "T1078 - Valid Accounts",
        "detection_logic": "Successful login from a geographically unusual source shortly after another login.",
        "description": "Detects suspicious account access patterns that may indicate compromised credentials."
    },
    {
        "rule_name": "Potential Credential Dumping",
        "severity": "Critical",
        "mitre_technique": "T1003 - OS Credential Dumping",
        "detection_logic": "Command line or alert content contains credential dumping terms such as mimikatz or lsass.",
        "description": "Identifies behavior associated with credential theft and post-compromise activity."
    }
]
