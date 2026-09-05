"""PR Security Gate Demo Fixture - Resolved with Context Manager."""


def read_data():
    with open("data.txt") as f:
        return f.read()
