import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from detection import run_all_detections


def test_advanced_detections_find_critical_alerts():
    logs = [
        {"timestamp":"2026-05-18T12:00:00","event_type":"login_success","username":"admin","src_ip":"1.1.1.1","country":"US","message":"ok"},
        {"timestamp":"2026-05-18T12:30:00","event_type":"login_success","username":"admin","src_ip":"2.2.2.2","country":"DE","message":"ok"},
        {"timestamp":"2026-05-18T12:31:00","event_type":"process_start","username":"admin","src_ip":"2.2.2.2","message":"powershell.exe -EncodedCommand abc"},
        {"timestamp":"2026-05-18T12:32:00","event_type":"admin_group_change","username":"admin","src_ip":"2.2.2.2","message":"user added to local administrators group"},
    ]
    alerts = run_all_detections(logs)
    assert any(a["rule"] == "Impossible Travel" for a in alerts)
    assert any(a["rule"] == "Suspicious PowerShell Activity" for a in alerts)
    assert any(a["severity"] == "Critical" for a in alerts)
