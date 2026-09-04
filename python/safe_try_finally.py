"""Sample Python file demonstrating a safe file resource pattern using try/finally."""


def read_data_resilient(filename: str) -> str:
    """Safely reads file contents ensuring close() is always called in finally block."""
    f = open(filename, "r")
    try:
        data = f.read()
        return data
    finally:
        f.close()
