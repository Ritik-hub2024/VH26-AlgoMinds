"""Leak Case: Multiple database connections with one leaked."""

import sqlite3


def migrate_databases():
    db1 = sqlite3.connect("primary.db")
    db2 = sqlite3.connect("replica.db")
    rows = db1.execute("SELECT * FROM users").fetchall()
    db1.close()
    # LEAK: db2 is never closed
    return len(rows)
