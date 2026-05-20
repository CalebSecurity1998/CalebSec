import ipaddress
import re

SUSPICIOUS_TLDS = {
    "top", "xyz", "click", "zip", "mov", "tk", "gq", "cf", "ml", "work", "quest"
}

HIGH_RISK_KEYWORDS = [
    "login", "verify", "password", "account", "secure", "update", "wallet",
    "mfa", "2fa", "bank", "invoice", "giftcard", "reset", "authentication"
]

MALICIOUS_IP_RANGES = [
    "185.220.101.0/24",
    "45.83.64.0/24",
    "91.240.118.0/24"
]

def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False

def _ip_in_known_bad_range(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
        return any(ip in ipaddress.ip_network(net) for net in MALICIOUS_IP_RANGES)
    except ValueError:
        return False

def _looks_like_hash(value: str) -> bool:
    return bool(re.fullmatch(r"[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}", value.strip()))

def _domain_tld(value: str) -> str:
    clean = value.lower().strip().replace("http://", "").replace("https://", "").split("/")[0]
    parts = clean.split(".")
    return parts[-1] if len(parts) > 1 else ""

def _looks_random(value: str) -> bool:
    clean = re.sub(r"[^a-zA-Z0-9]", "", value)
    if len(clean) < 12:
        return False
    digits = sum(c.isdigit() for c in clean)
    consonant_runs = bool(re.search(r"[bcdfghjklmnpqrstvwxyz]{5,}", clean.lower()))
    return digits >= 4 or consonant_runs

def enrich_ioc(ioc_value: str, ioc_type: str = "auto") -> dict:
    value = (ioc_value or "").strip()
    lowered = value.lower()
    score = 0
    reasons = []

    if not value:
        return {
            "risk_score": 0,
            "verdict": "Unknown",
            "mitre_mapping": "N/A",
            "summary": "No IOC value was provided."
        }

    if ioc_type == "auto":
        if _is_ip(value):
            ioc_type = "ip"
        elif _looks_like_hash(value):
            ioc_type = "hash"
        elif "http://" in lowered or "https://" in lowered:
            ioc_type = "url"
        elif "." in value:
            ioc_type = "domain"
        else:
            ioc_type = "keyword"

    if ioc_type == "ip":
        try:
            ip = ipaddress.ip_address(value)
            if ip.is_private:
                score += 5
                reasons.append("Private/internal IP address; useful for internal investigation but not inherently malicious.")
            else:
                score += 25
                reasons.append("Public IP address observed in alert context.")

            if _ip_in_known_bad_range(value):
                score += 55
                reasons.append("IP address matches a locally defined high-risk range.")
        except ValueError:
            score += 10
            reasons.append("Invalid IP format provided.")

    if ioc_type in {"domain", "url"}:
        tld = _domain_tld(value)
        if tld in SUSPICIOUS_TLDS:
            score += 30
            reasons.append(f"Suspicious or frequently abused top-level domain: .{tld}")

        keyword_hits = [word for word in HIGH_RISK_KEYWORDS if word in lowered]
        if keyword_hits:
            score += min(35, 8 * len(keyword_hits))
            reasons.append("Contains phishing-themed keywords: " + ", ".join(keyword_hits[:5]))

        if _looks_random(value):
            score += 25
            reasons.append("Domain or URL appears randomly generated or unusual.")

        if lowered.startswith("http://"):
            score += 15
            reasons.append("Uses unencrypted HTTP.")

    if ioc_type == "hash":
        score += 35
        reasons.append("File hash indicator should be checked against malware reputation sources.")

    if ioc_type == "command":
        suspicious_terms = ["powershell", "-enc", "encodedcommand", "mimikatz", "certutil", "rundll32", "regsvr32"]
        hits = [term for term in suspicious_terms if term in lowered]
        if hits:
            score += min(80, 20 * len(hits))
            reasons.append("Suspicious command-line behavior detected: " + ", ".join(hits))

    score = max(0, min(score, 100))

    if score >= 75:
        verdict = "High Risk"
    elif score >= 45:
        verdict = "Suspicious"
    elif score >= 20:
        verdict = "Needs Review"
    else:
        verdict = "Low Risk"

    mitre_mapping = map_to_mitre(ioc_type, lowered)

    if not reasons:
        reasons.append("No strong local risk indicators were identified.")

    return {
        "risk_score": score,
        "verdict": verdict,
        "mitre_mapping": mitre_mapping,
        "summary": " ".join(reasons)
    }

def map_to_mitre(ioc_type: str, value: str) -> str:
    if ioc_type in {"domain", "url"} and any(word in value for word in ["login", "verify", "password", "account"]):
        return "T1566 - Phishing"
    if ioc_type == "ip":
        return "T1071 - Application Layer Protocol"
    if ioc_type == "command" and "powershell" in value:
        return "T1059.001 - PowerShell"
    if ioc_type == "hash":
        return "T1204 - User Execution"
    return "TTP Review Required"
