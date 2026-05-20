import sqlite3
from datetime import datetime
from enhanced_demo_data import ENHANCED_SOC_ALERTS, DETECTION_RULES

DB_NAME = "siem.db"

def get_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def init_workflow_tables():
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS analyst_activity (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at TEXT NOT NULL,
        actor TEXT NOT NULL,
        action TEXT NOT NULL,
        details TEXT
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS detection_rules (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        rule_name TEXT NOT NULL,
        severity TEXT NOT NULL,
        mitre_technique TEXT,
        detection_logic TEXT,
        description TEXT,
        enabled INTEGER DEFAULT 1
    )
    """)

    existing_rules = cur.execute("SELECT COUNT(*) AS count FROM detection_rules").fetchone()["count"]
    if existing_rules == 0:
        for rule in DETECTION_RULES:
            cur.execute("""
            INSERT INTO detection_rules (
                rule_name, severity, mitre_technique, detection_logic, description, enabled
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """, (
                rule["rule_name"],
                rule["severity"],
                rule["mitre_technique"],
                rule["detection_logic"],
                rule["description"],
                1
            ))

    conn.commit()
    conn.close()

def log_activity(actor, action, details=""):
    conn = get_connection()
    conn.execute("""
    INSERT INTO analyst_activity (created_at, actor, action, details)
    VALUES (?, ?, ?, ?)
    """, (
        datetime.utcnow().isoformat(timespec="seconds") + "Z",
        actor,
        action,
        details
    ))
    conn.commit()
    conn.close()

def get_recent_activity(limit=25):
    conn = get_connection()
    rows = conn.execute("""
    SELECT * FROM analyst_activity
    ORDER BY id DESC
    LIMIT ?
    """, (limit,)).fetchall()
    conn.close()
    return [dict(row) for row in rows]

def get_detection_rules():
    conn = get_connection()
    rows = conn.execute("""
    SELECT * FROM detection_rules
    ORDER BY 
        CASE severity
            WHEN 'Critical' THEN 1
            WHEN 'High' THEN 2
            WHEN 'Medium' THEN 3
            WHEN 'Low' THEN 4
            ELSE 5
        END,
        rule_name ASC
    """).fetchall()
    conn.close()
    return [dict(row) for row in rows]

def seed_enhanced_demo_data():
    """
    This adds realistic analyst activity and optional enhanced alerts.

    Note:
    This function safely logs demo activity. If your existing app has a compatible
    soc_alerts table from the previous SOC upgrade, it will also insert enhanced alerts.
    """
    conn = get_connection()
    cur = conn.cursor()

    demo_actions = [
        ("system", "Seeded enhanced demo workflow", "Loaded realistic SOC activity, detection rules, and analyst workflow events."),
        ("analyst_caleb", "Reviewed brute force alert", "Mapped suspicious login behavior to T1110 - Brute Force."),
        ("analyst_caleb", "Escalated suspicious PowerShell alert", "Encoded command behavior requires deeper endpoint investigation."),
        ("analyst_caleb", "Created case from phishing alert", "Suspicious credential-harvesting domain identified."),
        ("system", "Updated IOC enrichment history", "Threat intelligence scoring generated for suspicious IP and domain indicators.")
    ]

    for actor, action, details in demo_actions:
        cur.execute("""
        INSERT INTO analyst_activity (created_at, actor, action, details)
        VALUES (?, ?, ?, ?)
        """, (
            datetime.utcnow().isoformat(timespec="seconds") + "Z",
            actor,
            action,
            details
        ))

    table_check = cur.execute("""
    SELECT name FROM sqlite_master
    WHERE type='table' AND name='soc_alerts'
    """).fetchone()

    if table_check:
        for alert in ENHANCED_SOC_ALERTS:
            cur.execute("""
            INSERT INTO soc_alerts (
                created_at, title, severity, source_ip, destination_ip, username,
                ioc_value, ioc_type, mitre_technique, description,
                status, analyst_notes, assigned_to, risk_score, enrichment_summary
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                alert["status"],
                alert["analyst_notes"],
                alert["assigned_to"],
                alert["risk_score"],
                alert["enrichment_summary"]
            ))

    conn.commit()
    conn.close()
