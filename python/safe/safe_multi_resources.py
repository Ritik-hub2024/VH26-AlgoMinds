"""Safe Case: Both file and database connection safely closed in finally."""

import sqlite3


def export_user_table():
    f = open("users.dump", "w")
    conn = sqlite3.connect("app.db")
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT id, name FROM users")
        for row in cursor.fetchall():
            f.write(f"{row[0]}:{row[1]}\n")
    finally:
        f.close()
        conn.close()
    return True
