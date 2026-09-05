"""Deterministic Unknown Ownership-Transfer Demonstration Fixture for LeakGuard Demo."""


def process():
    f = open("data.txt")
    send_to_worker(f)
