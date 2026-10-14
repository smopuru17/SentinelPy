import sqlite3
from pathlib import Path


# Store the database beside database.py
DB_FILE = Path(__file__).resolve().parent / "sentinelpy.db"

def initialize_db():
    """Create the alerts table if it doesn't exist."""


    with sqlite3.connect(DB_FILE) as conn:

        conn.execute("""
            CREATE TABLE IF NOT EXISTS alerts  (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT NOT NULL,
                    attack_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    mitre_attack TEXT,
                    UNIQUE(ip_address, attack_type, timestamp)
                )
            """)

    print("DB initialized sucessfully.")


def save_alerts(alerts):
    """Save detected security alerts."""

    with sqlite3.connect(DB_FILE) as conn:

        for alert in alerts:

            conn.execute("""
            INSERT OR IGNORE INTO alerts (
                    ip_address,
                    attack_type,
                    severity,
                    timestamp,
                    mitre_attack
                )
                VALUES (?, ?, ?, ?, ?)
            """, (
                alert["ip_address"],
                alert["attack_type"],
                alert["severity"],
                alert["timestamp"],
                alert["mitre_attack"]
            ))
    print("Alerts saved successfully.")

def get_alerts():
    """Retrieve all previously saved alerts."""

    with sqlite3.connect(DB_FILE) as conn:

        conn.row_factory = sqlite3.Row

        rows = conn.execute("""
        SELECT * FROM alerts
        ORDER BY timestamp DESC
        """).fetchall()

    return[dict(row) for row in rows]


