"""Safe Case: SQLite connection closed in finally block."""

import sqlite3


def fetch_config_value(key: str):
    conn = sqlite3.connect("settings.db")
    try:
        cur = conn.cursor()
        cur.execute("SELECT val FROM settings WHERE k = ?", (key,))
        row = cur.fetchone()
        return row[0] if row else None
    finally:
        conn.close()
