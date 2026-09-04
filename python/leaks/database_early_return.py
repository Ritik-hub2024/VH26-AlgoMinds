import sqlite3


def get_users(flag):
    conn = sqlite3.connect("app.db")
    if flag:
        return None
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users")
    res = cursor.fetchall()
    conn.close()
    return res
