"""Unknown Case: SQLite connection passed to external migration handler."""

import sqlite3


def run_migration_externally(connection):
    pass


def setup_database_schema():
    conn = sqlite3.connect("service.db")
    # Transferred to external migration handler
    run_migration_externally(conn)
    return "migration_dispatched"
