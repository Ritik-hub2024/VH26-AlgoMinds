"""Test case: File safely managed with context manager."""

def read_config_with(filename: str):
    with open(filename, "r") as f:
        return f.read()
