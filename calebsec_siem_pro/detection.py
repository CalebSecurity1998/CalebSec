from __future__ import annotations

import json
import os
from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, List

Alert = Dict[str, Any]
Log = Dict[str, Any]

MITRE = {
    "brute_force": "T1110 - Brute Force",
    "valid_accounts": "T1078 - Valid Accounts",
    "powershell": "T1059.001 - PowerShell",
    "command": "T1059 - Command and Scripting Interpreter",
    "privilege": "T1068 - Exploitation for Privilege Escalation",
    "account_create": "T1136 - Create Account",
    "c2": "T1071 - Application Layer Protocol",
    "ioc": "T1105 - Ingress Tool Transfer",
    "exfil": "T1041 - Exfiltration Over C2 Channel",
}

SEVERITY_SCORES = {"Informational": 10, "Low": 25, "Medium": 50, "High": 75, "Critical": 95}
COUNTRY_COORDS = {
    "US": (39.8283, -98.5795), "CA": (56.1304, -106.3468), "GB": (55.3781, -3.4360),
    "DE": (51.1657, 10.4515), "FR": (46.2276, 2.2137), "NL": (52.1326, 5.2913),
    "RU": (61.5240, 105.3188), "CN": (35.8617, 104.1954), "BR": (-14.2350, -51.9253),
}


def _alert(rule: str, severity: str, src_ip: str, description: str, mitre: str, tactic: str, **extra: Any) -> Alert:
    score = extra.pop("risk_score", SEVERITY_SCORES.get(severity, 50))
    return {
        "rule": rule,
        "severity": severity,
        "src_ip": src_ip or "unknown",
        "description": description,
        "mitre": mitre,
        "tactic": tactic,
        "risk_score": score,
        **extra,
    }


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00").replace("+00:00", ""))
    except Exception:
        return None


def load_iocs(path: str = "threat_intel/iocs.json") -> dict:
    if not os.path.exists(path):
        return {"malicious_ips": [], "malicious_domains": [], "malicious_hashes": []}
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def detect_brute_force(logs: List[Log]) -> List[Alert]:
    alerts, failed_counts = [], defaultdict(int)
    for log in logs:
        ip = log.get("src_ip", "unknown")
        if log.get("event_type") == "login_failed":
            failed_counts[ip] += 1
            if failed_counts[ip] == 5:
                alerts.append(_alert("Multiple Failed Login Attempts", "High", ip, f"5 failed login attempts detected from {ip}", MITRE["brute_force"], "Credential Access"))
        if log.get("event_type") == "login_success" and failed_counts.get(ip, 0) >= 3:
            alerts.append(_alert("Successful Login After Failures", "Critical", ip, f"Successful login from {ip} after repeated failures", MITRE["brute_force"], "Credential Access"))
    return alerts


def detect_after_hours(logs: List[Log]) -> List[Alert]:
    alerts = []
    for log in logs:
        if log.get("event_type") == "login_success":
            ts = _parse_time(log.get("timestamp"))
            if ts and (ts.hour < 7 or ts.hour > 19):
                alerts.append(_alert("Login Outside Business Hours", "Medium", log.get("src_ip"), f"Login by {log.get('username', 'unknown')} outside normal hours", MITRE["valid_accounts"], "Defense Evasion"))
    return alerts


def detect_suspicious_commands(logs: List[Log]) -> List[Alert]:
    alerts = []
    keywords = ["nmap", "mimikatz", "sudo", "chmod 777", "whoami", "net user", "shadow", "lsass"]
    powershell_terms = ["encodedcommand", "invoke-webrequest", "downloadstring", "iex", "bypass", "frombase64string"]
    for log in logs:
        msg = log.get("message", "").lower()
        ip = log.get("src_ip", "unknown")
        for term in powershell_terms:
            if term in msg:
                alerts.append(_alert("Suspicious PowerShell Activity", "High", ip, f"PowerShell abuse keyword detected: {term}", MITRE["powershell"], "Execution"))
                break
        for word in keywords:
            if word in msg:
                alerts.append(_alert("Suspicious Command Detected", "High", ip, f"Suspicious keyword detected: {word}", MITRE["command"], "Execution"))
                break
    return alerts


def detect_privilege_escalation(logs: List[Log]) -> List[Alert]:
    alerts = []
    phrases = ["added to local administrators", "admin group", "sudoers", "root login", "privilege escalation", "new admin"]
    for log in logs:
        msg = log.get("message", "").lower()
        if log.get("event_type") in {"admin_group_change", "privilege_change", "user_created"} or any(p in msg for p in phrases):
            alerts.append(_alert("Privilege Escalation or Admin Change", "Critical", log.get("src_ip"), f"Privileged account activity by {log.get('username', 'unknown')}", MITRE["privilege"], "Privilege Escalation"))
    return alerts


def detect_ioc_matches(logs: List[Log]) -> List[Alert]:
    alerts, iocs = [], load_iocs()
    ips, domains, hashes = set(iocs.get("malicious_ips", [])), set(iocs.get("malicious_domains", [])), set(iocs.get("malicious_hashes", []))
    for log in logs:
        ip = log.get("src_ip", "unknown")
        dest_ip = log.get("dest_ip", "")
        domain = log.get("dest_domain", "")
        file_hash = log.get("file_hash", "")
        if ip in ips or dest_ip in ips:
            alerts.append(_alert("Threat Intel IP Match", "Critical", ip, f"Known malicious IP observed: {dest_ip or ip}", MITRE["ioc"], "Command and Control"))
        if domain in domains:
            alerts.append(_alert("Threat Intel Domain Match", "Critical", ip, f"Known malicious domain observed: {domain}", MITRE["c2"], "Command and Control"))
        if file_hash in hashes:
            alerts.append(_alert("Malware Hash Match", "Critical", ip, f"Known malicious file hash observed: {file_hash}", MITRE["ioc"], "Command and Control"))
    return alerts


def detect_impossible_travel(logs: List[Log]) -> List[Alert]:
    alerts, by_user = [], defaultdict(list)
    for log in logs:
        if log.get("event_type") == "login_success" and log.get("country"):
            ts = _parse_time(log.get("timestamp"))
            if ts:
                by_user[log.get("username", "unknown")].append((ts, log))
    for user, events in by_user.items():
        events.sort(key=lambda x: x[0])
        for (t1, a), (t2, b) in zip(events, events[1:]):
            c1, c2 = a.get("country"), b.get("country")
            hours = max((t2 - t1).total_seconds() / 3600, 0.01)
            if c1 != c2 and c1 in COUNTRY_COORDS and c2 in COUNTRY_COORDS and hours < 4:
                alerts.append(_alert("Impossible Travel", "Critical", b.get("src_ip"), f"User {user} logged in from {c1} then {c2} within {hours:.1f} hours", MITRE["valid_accounts"], "Initial Access"))
    return alerts


def detect_beaconing(logs: List[Log]) -> List[Alert]:
    alerts, pairs = [], defaultdict(list)
    for log in logs:
        if log.get("event_type") in {"network_connection", "dns_query", "proxy"}:
            key = (log.get("src_ip", "unknown"), log.get("dest_ip") or log.get("dest_domain") or "unknown")
            ts = _parse_time(log.get("timestamp"))
            if ts:
                pairs[key].append(ts)
    for (src, dest), times in pairs.items():
        if len(times) >= 5:
            times.sort()
            alerts.append(_alert("Possible Beaconing Behavior", "High", src, f"Repeated outbound connections from {src} to {dest}", MITRE["c2"], "Command and Control"))
    return alerts


def run_all_detections(logs: List[Log]) -> List[Alert]:
    all_alerts: List[Alert] = []
    for detector in [
        detect_brute_force,
        detect_after_hours,
        detect_suspicious_commands,
        detect_privilege_escalation,
        detect_ioc_matches,
        detect_impossible_travel,
        detect_beaconing,
    ]:
        all_alerts.extend(detector(logs))
    return all_alerts


def mitre_heatmap(alerts: List[Alert]) -> dict:
    counts = defaultdict(int)
    for alert in alerts:
        tactic = alert.get("tactic") or "Uncategorized"
        counts[tactic] += 1
    return dict(sorted(counts.items(), key=lambda item: item[1], reverse=True))
