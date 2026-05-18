import subprocess
from datetime import datetime

def collect_macos_logs():
    cmd = [
        "log", "show",
        "--last", "10m",
        "--style", "compact",
        "--predicate",
        'eventMessage CONTAINS[c] "login" OR eventMessage CONTAINS[c] "authentication" OR eventMessage CONTAINS[c] "failed" OR eventMessage CONTAINS[c] "sudo" OR eventMessage CONTAINS[c] "denied"'
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        lines = result.stdout.splitlines()
    except Exception as e:
        return [{
            "timestamp": datetime.now().isoformat(),
            "event_type": "collector_error",
            "username": "system",
            "src_ip": "localhost",
            "message": str(e)
        }]

    logs = []

    for line in lines[:75]:
        logs.append({
            "timestamp": datetime.now().isoformat(),
            "event_type": "macos_log",
            "username": "system",
            "src_ip": "localhost",
            "message": line
        })

    return logs
