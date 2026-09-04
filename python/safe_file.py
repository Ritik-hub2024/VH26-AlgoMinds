"""Sample Python file demonstrating a safe file resource pattern.

open() is directly followed by close() before function exit.
"""


def read_config(path: str) -> str:
    """Read configuration safely with explicit open() and close()."""
    f = open(path, "r", encoding="utf-8")
    content = f.read()
    f.close()
    return content


if __name__ == "__main__":
    pass
