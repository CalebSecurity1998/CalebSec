import sqlite3
from datetime import datetime

DB = "siem.db"


def connect():
    return sqlite3.connect(DB)


def ensure_column(cursor, table, column_name, column_definition):
    cursor.execute(f"PRAGMA table_info({table})")
    existing_columns = [row[1] for row in cursor.fetchall()]

    if column_name not in existing_columns:
        cursor.execute(f"ALTER TABLE {table} ADD COLUMN {column_name} {column_definition}")


def init_db():
    con = connect()
    cur = con.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        event_type TEXT,
        username TEXT,
        src_ip TEXT,
        message TEXT
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        rule TEXT,
        severity TEXT,
        src_ip TEXT,
        description TEXT,
        mitre TEXT,
        status TEXT DEFAULT 'Open',
        notes TEXT DEFAULT '',
        occurrence_count INTEGER DEFAULT 1,
        first_seen TEXT DEFAULT '',
        last_seen TEXT DEFAULT ''
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS cases (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        alert_id INTEGER,
        title TEXT,
        status TEXT DEFAULT 'Open',
        notes TEXT DEFAULT ''
    )
    """)

    ensure_column(cur, "alerts", "occurrence_count", "INTEGER DEFAULT 1")
    ensure_column(cur, "alerts", "first_seen", "TEXT DEFAULT ''")
    ensure_column(cur, "alerts", "last_seen", "TEXT DEFAULT ''")

    now = datetime.now().isoformat(timespec="seconds")

    cur.execute("""
    UPDATE alerts
    SET occurrence_count = COALESCE(occurrence_count, 1)
    WHERE occurrence_count IS NULL
    """)

    cur.execute("""
    UPDATE alerts
    SET first_seen = ?
    WHERE first_seen IS NULL OR first_seen = ''
    """, (now,))

    cur.execute("""
    UPDATE alerts
    SET last_seen = ?
    WHERE last_seen IS NULL OR last_seen = ''
    """, (now,))

    con.commit()
    con.close()


def insert_log(log):
    con = connect()
    cur = con.cursor()

    cur.execute("""
    INSERT INTO logs (
        timestamp,
        event_type,
        username,
        src_ip,
        message
    )
    VALUES (?, ?, ?, ?, ?)
    """, (
        log.get("timestamp", ""),
        log.get("event_type", ""),
        log.get("username", ""),
        log.get("src_ip", ""),
        log.get("message", "")
    ))

    con.commit()
    con.close()


def insert_alert(alert):
    con = connect()
    cur = con.cursor()

    now = datetime.now().isoformat(timespec="seconds")

    cur.execute("""
    SELECT id, occurrence_count
    FROM alerts
    WHERE rule = ?
      AND src_ip = ?
      AND description = ?
    """, (
        alert["rule"],
        alert["src_ip"],
        alert["description"]
    ))

    existing = cur.fetchone()

    if existing:
        alert_id, current_count = existing
        new_count = (current_count or 1) + 1

        cur.execute("""
        UPDATE alerts
        SET occurrence_count = ?,
            last_seen = ?,
            severity = ?,
            mitre = ?
        WHERE id = ?
        """, (
            new_count,
            now,
            alert["severity"],
            alert["mitre"],
            alert_id
        ))
    else:
        cur.execute("""
        INSERT INTO alerts (
            rule,
            severity,
            src_ip,
            description,
            mitre,
            status,
            notes,
            occurrence_count,
            first_seen,
            last_seen
        )
        VALUES (?, ?, ?, ?, ?, 'Open', '', 1, ?, ?)
        """, (
            alert["rule"],
            alert["severity"],
            alert["src_ip"],
            alert["description"],
            alert["mitre"],
            now,
            now
        ))

    con.commit()
    con.close()


def get_logs():
    con = connect()
    cur = con.cursor()

    cur.execute("""
    SELECT timestamp, event_type, username, src_ip, message
    FROM logs
    ORDER BY id DESC
    """)

    rows = cur.fetchall()
    con.close()

    return [
        {
            "timestamp": row[0],
            "event_type": row[1],
            "username": row[2],
            "src_ip": row[3],
            "message": row[4]
        }
        for row in rows
    ]


def get_alerts():
    con = connect()
    cur = con.cursor()

    cur.execute("""
    SELECT
        id,
        rule,
        severity,
        src_ip,
        description,
        mitre,
        status,
        notes,
        occurrence_count,
        first_seen,
        last_seen
    FROM alerts
    ORDER BY id DESC
    """)

    rows = cur.fetchall()
    con.close()

    return [
        {
            "id": row[0],
            "rule": row[1],
            "severity": row[2],
            "src_ip": row[3],
            "description": row[4],
            "mitre": row[5],
            "status": row[6],
            "notes": row[7],
            "occurrence_count": row[8],
            "first_seen": row[9],
            "last_seen": row[10]
        }
        for row in rows
    ]


def update_alert(alert_id, status, notes):
    con = connect()
    cur = con.cursor()

    cur.execute("""
    UPDATE alerts
    SET status = ?, notes = ?
    WHERE id = ?
    """, (status, notes, alert_id))

    con.commit()
    con.close()


def delete_alert(alert_id):
    con = connect()
    cur = con.cursor()

    cur.execute("DELETE FROM cases WHERE alert_id = ?", (alert_id,))
    cur.execute("DELETE FROM alerts WHERE id = ?", (alert_id,))

    con.commit()
    con.close()


def create_case(alert_id, title, notes):
    con = connect()
    cur = con.cursor()

    cur.execute("""
    INSERT INTO cases (
        alert_id,
        title,
        status,
        notes
    )
    VALUES (?, ?, 'Open', ?)
    """, (alert_id, title, notes))

    con.commit()
    con.close()


def get_cases():
    con = connect()
    cur = con.cursor()

    cur.execute("""
    SELECT id, alert_id, title, status, notes
    FROM cases
    ORDER BY id DESC
    """)

    rows = cur.fetchall()
    con.close()

    return [
        {
            "id": row[0],
            "alert_id": row[1],
            "title": row[2],
            "status": row[3],
            "notes": row[4]
        }
        for row in rows
    ]


def update_case(case_id, status, notes):
    con = connect()
    cur = con.cursor()

    cur.execute("""
    UPDATE cases
    SET status = ?, notes = ?
    WHERE id = ?
    """, (status, notes, case_id))

    con.commit()
    con.close()


def delete_case(case_id):
    con = connect()
    cur = con.cursor()

    cur.execute("DELETE FROM cases WHERE id = ?", (case_id,))

    con.commit()
    con.close()


def clear_db():
    con = connect()
    cur = con.cursor()

    cur.execute("DELETE FROM logs")
    cur.execute("DELETE FROM alerts")
    cur.execute("DELETE FROM cases")

    con.commit()
    con.close()
