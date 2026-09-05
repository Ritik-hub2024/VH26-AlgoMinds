"""Deterministic Leak Demonstration Fixture for LeakGuard Demo."""


def read_data():
    f = open("data.txt")
    if error:
        return None
    return f.read()
