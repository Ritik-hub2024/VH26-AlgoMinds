"""Sample Python file demonstrating an unclosed file resource leak.

open() is called, but f.close() is never invoked anywhere.
"""


def load_user_records(filepath: str) -> list[str]:
    """Leaking function: opens file handle but never closes it."""
    f = open(filepath, "r")
    records = [line.strip() for line in f.readlines()]
    return records
