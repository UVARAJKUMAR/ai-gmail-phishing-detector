import sqlite3
from datetime import datetime

DB_NAME = "phishing_detector.db"


def get_connection():
    return sqlite3.connect(DB_NAME)


def init_db():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scanned_emails (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            uid TEXT UNIQUE,
            message_id TEXT,
            sender TEXT,
            subject TEXT,
            risk_level TEXT,
            score INTEGER,
            reasons TEXT,
            alert_sent INTEGER DEFAULT 0,
            scanned_at TEXT
        )
    """)

    # --------------------------------------------------------
    # DATABASE MIGRATION
    # --------------------------------------------------------
    # CREATE TABLE IF NOT EXISTS does not modify an existing table.
    # Older versions of this project were created without alert_sent,
    # so add the column when upgrading an existing database.
    cursor.execute("PRAGMA table_info(scanned_emails)")
    columns = {row[1] for row in cursor.fetchall()}

    if "alert_sent" not in columns:
        cursor.execute(
            "ALTER TABLE scanned_emails "
            "ADD COLUMN alert_sent INTEGER DEFAULT 0"
        )

    conn.commit()
    conn.close()


def already_scanned(uid):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT 1 FROM scanned_emails WHERE uid = ? LIMIT 1",
        (uid,)
    )

    result = cursor.fetchone()
    conn.close()

    return result is not None


def save_result(
    uid,
    message_id,
    sender,
    subject,
    risk_level,
    score,
    reasons
):
    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("""
            INSERT INTO scanned_emails
            (
                uid,
                message_id,
                sender,
                subject,
                risk_level,
                score,
                reasons,
                alert_sent,
                scanned_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?)
        """, (
            uid,
            message_id,
            sender,
            subject,
            risk_level,
            score,
            "\n".join(reasons)
            if isinstance(reasons, list)
            else str(reasons),
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ))

        conn.commit()

    except sqlite3.IntegrityError:
        pass

    finally:
        conn.close()


def alert_already_sent(uid):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT alert_sent
        FROM scanned_emails
        WHERE uid = ?
        LIMIT 1
    """, (uid,))

    result = cursor.fetchone()
    conn.close()

    if result is None:
        return False

    return result[0] == 1


def mark_alert_sent(uid):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE scanned_emails
        SET alert_sent = 1
        WHERE uid = ?
    """, (uid,))

    conn.commit()
    conn.close()