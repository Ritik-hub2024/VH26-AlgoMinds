import sqlite3


def get_users():
    conn = sqlite3.connect("app.db")
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users")
        return cursor.fetchall()
    finally:
        conn.close()
