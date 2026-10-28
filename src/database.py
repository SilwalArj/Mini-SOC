
import sqlite3
from models import Event


def get_connection():
    return sqlite3.connect("data/soc.db")


def create_tables():
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            event_type TEXT NOT NULL,
            username TEXT,
            source_ip TEXT,
            severity TEXT,
            raw_log TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            alert_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            source_ip TEXT,
            description TEXT,
            status TEXT NOT NULL
        )
    """)

    connection.commit()
    connection.close()


def insert_event(event):
    connection = get_connection()
    cursor = connection.cursor()

    # Avoid inserting an exact log line twice.
    cursor.execute(
        "SELECT 1 FROM events WHERE raw_log = ? LIMIT 1",
        (event.raw_log,)
    )

    if cursor.fetchone():
        connection.close()
        return False

    cursor.execute("""
        INSERT INTO events (
            timestamp,
            event_type,
            username,
            source_ip,
            severity,
            raw_log
        )
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        event.timestamp,
        event.event_type,
        event.username,
        event.source_ip,
        event.severity,
        event.raw_log
    ))

    connection.commit()
    connection.close()
    return True


def insert_alert(alert):
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT 1
        FROM alerts
        WHERE alert_type = ?
          AND source_ip = ?
          AND status IN ('NEW', 'INVESTIGATING')
        LIMIT 1
    """, (
        alert["alert_type"],
        alert["source_ip"]
    ))

    if cursor.fetchone():
        connection.close()
        return False

    cursor.execute("""
        INSERT INTO alerts (
            timestamp,
            alert_type,
            severity,
            source_ip,
            description,
            status
        )
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        alert["timestamp"],
        alert["alert_type"],
        alert["severity"],
        alert["source_ip"],
        alert["description"],
        alert["status"]
    ))

    connection.commit()
    connection.close()
    return True



def get_events():
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            timestamp,
            event_type,
            username,
            source_ip,
            severity,
            raw_log
        FROM events
        ORDER BY id
    """)

    rows = cursor.fetchall()
    connection.close()

    events = []

    for row in rows:
        event = Event(
            timestamp=row[0],
            event_type=row[1],
            username=row[2],
            source_ip=row[3],
            severity=row[4],
            raw_log=row[5],
        )
        events.append(event)

    return events


def get_alerts(severity=None):
    connection = get_connection()
    cursor = connection.cursor()

    if severity is None:
        cursor.execute("""
            SELECT id, timestamp, alert_type, severity,
                   source_ip, description, status
            FROM alerts
            ORDER BY id DESC
        """)
    else:
        cursor.execute("""
            SELECT id, timestamp, alert_type, severity,
                   source_ip, description, status
            FROM alerts
            WHERE severity = ?
            ORDER BY id DESC
        """, (severity.upper(),))

    rows = cursor.fetchall()
    connection.close()
    return rows


def update_alert_status(alert_id, status):
    valid_statuses = {"NEW", "INVESTIGATING", "RESOLVED"}

    status = status.upper()

    if status not in valid_statuses:
        raise ValueError(f"Invalid alert status: {status}")

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        UPDATE alerts
        SET status = ?
        WHERE id = ?
    """, (status, alert_id))

    updated = cursor.rowcount > 0

    connection.commit()
    connection.close()

    return updated
