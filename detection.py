from datetime import datetime

def run_all_detections(logs):
    alerts = []
    failed_counts = {}

    for log in logs:
        ip = log.get("src_ip", "unknown")
        event = log.get("event_type", "")
        message = log.get("message", "").lower()

        if event == "login_failed":
            failed_counts[ip] = failed_counts.get(ip, 0) + 1
            if failed_counts[ip] == 5:
                alerts.append({"rule":"Multiple Failed Login Attempts","severity":"High","src_ip":ip,"description":f"5 failed login attempts detected from {ip}","mitre":"T1110 - Brute Force"})

        if event == "login_success" and failed_counts.get(ip, 0) >= 3:
            alerts.append({"rule":"Successful Login After Failures","severity":"Critical","src_ip":ip,"description":f"Successful login from {ip} after failures","mitre":"T1110 - Brute Force"})

        if event == "login_success":
            hour = datetime.fromisoformat(log["timestamp"]).hour
            if hour < 7 or hour > 19:
                alerts.append({"rule":"Login Outside Business Hours","severity":"Medium","src_ip":ip,"description":f"Login by {log.get('username')} outside normal hours","mitre":"T1078 - Valid Accounts"})

        for word in ["nmap", "mimikatz", "sudo", "chmod 777", "whoami"]:
            if word in message:
                alerts.append({"rule":"Suspicious Command Detected","severity":"High","src_ip":ip,"description":f"Suspicious keyword detected: {word}","mitre":"T1059 - Command and Scripting Interpreter"})

    return alerts
