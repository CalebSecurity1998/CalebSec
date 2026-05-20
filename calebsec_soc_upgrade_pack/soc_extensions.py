import sqlite3
from datetime import datetime
from threat_intel import enrich_ioc

DB_NAME = "siem.db"

def get_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def init_soc_tables():
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS soc_alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at TEXT NOT NULL,
        title TEXT NOT NULL,
        severity TEXT NOT NULL,
        source_ip TEXT,
        destination_ip TEXT,
        username TEXT,
        ioc_value TEXT,
        ioc_type TEXT,
        mitre_technique TEXT,
        description TEXT,
        status TEXT DEFAULT 'New',
        analyst_notes TEXT DEFAULT '',
        assigned_to TEXT DEFAULT '',
        risk_score INTEGER DEFAULT 0,
        enrichment_summary TEXT DEFAULT ''
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS ioc_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        searched_at TEXT NOT NULL,
        ioc_value TEXT NOT NULL,
        ioc_type TEXT NOT NULL,
        risk_score INTEGER NOT NULL,
        verdict TEXT NOT NULL,
        mitre_mapping TEXT,
        summary TEXT
    )
    """)

    conn.commit()
    conn.close()

def generate_sample_soc_alerts():
    sample_alerts = [
        {
            "title": "Potential Brute Force Login Attempt",
            "severity": "High",
            "source_ip": "185.220.101.42",
            "destination_ip": "10.0.0.25",
            "username": "admin",
            "ioc_value": "185.220.101.42",
            "ioc_type": "ip",
            "mitre_technique": "T1110 - Brute Force",
            "description": "Multiple failed login attempts were observed against the admin account from a suspicious external IP address."
        },
        {
            "title": "Suspicious PowerShell Activity",
            "severity": "Critical",
            "source_ip": "10.0.0.44",
            "destination_ip": "10.0.0.10",
            "username": "caleb",
            "ioc_value": "powershell -enc",
            "ioc_type": "command",
            "mitre_technique": "T1059.001 - PowerShell",
            "description": "Encoded PowerShell behavior was detected, which may indicate script-based execution or defense evasion."
        },
        {
            "title": "Possible Malware Beaconing",
            "severity": "Critical",
            "source_ip": "10.0.0.31",
            "destination_ip": "45.83.64.12",
            "username": "workstation-031",
            "ioc_value": "45.83.64.12",
            "ioc_type": "ip",
            "mitre_technique": "T1071 - Application Layer Protocol",
            "description": "Repeated outbound traffic was observed at regular intervals, which may indicate command-and-control beaconing."
        },
        {
            "title": "Phishing Link Detected",
            "severity": "Medium",
            "source_ip": "10.0.0.18",
            "destination_ip": "192.0.2.55",
            "username": "user01",
            "ioc_value": "login-security-update.example.com",
            "ioc_type": "domain",
            "mitre_technique": "T1566 - Phishing",
            "description": "A suspicious domain resembling a credential harvesting page was detected in user-submitted email content."
        }
    ]

    conn = get_connection()
    cur = conn.cursor()

    for alert in sample_alerts:
        enrichment = enrich_ioc(alert["ioc_value"], alert["ioc_type"])
        cur.execute("""
        INSERT INTO soc_alerts (
            created_at, title, severity, source_ip, destination_ip, username,
            ioc_value, ioc_type, mitre_technique, description,
            risk_score, enrichment_summary
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            datetime.utcnow().isoformat(timespec="seconds") + "Z",
            alert["title"],
            alert["severity"],
            alert["source_ip"],
            alert["destination_ip"],
            alert["username"],
            alert["ioc_value"],
            alert["ioc_type"],
            alert["mitre_technique"],
            alert["description"],
            enrichment["risk_score"],
            enrichment["summary"]
        ))

    conn.commit()
    conn.close()

def get_triage_alerts(status=None, severity=None):
    conn = get_connection()
    cur = conn.cursor()

    query = "SELECT * FROM soc_alerts WHERE 1=1"
    params = []

    if status:
        query += " AND status = ?"
        params.append(status)

    if severity:
        query += " AND severity = ?"
        params.append(severity)

    query += " ORDER BY id DESC"

    rows = cur.execute(query, params).fetchall()
    conn.close()
    return [dict(row) for row in rows]

def update_triage_alert(alert_id, status, analyst_notes, assigned_to):
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
    UPDATE soc_alerts
    SET status = ?, analyst_notes = ?, assigned_to = ?
    WHERE id = ?
    """, (status, analyst_notes, assigned_to, alert_id))

    conn.commit()
    conn.close()

def lookup_ioc(ioc_value, ioc_type):
    result = enrich_ioc(ioc_value, ioc_type)

    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
    INSERT INTO ioc_history (
        searched_at, ioc_value, ioc_type, risk_score, verdict, mitre_mapping, summary
    )
    VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        datetime.utcnow().isoformat(timespec="seconds") + "Z",
        ioc_value,
        ioc_type,
        result["risk_score"],
        result["verdict"],
        result["mitre_mapping"],
        result["summary"]
    ))

    conn.commit()
    conn.close()

    return result

def get_ioc_history():
    conn = get_connection()
    rows = conn.execute("SELECT * FROM ioc_history ORDER BY id DESC LIMIT 50").fetchall()
    conn.close()
    return [dict(row) for row in rows]
