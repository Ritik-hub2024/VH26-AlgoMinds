"""Deterministic Safe Demonstration Fixture for LeakGuard Demo."""


def read_data():
    with open("data.txt") as f:
        return f.read()
