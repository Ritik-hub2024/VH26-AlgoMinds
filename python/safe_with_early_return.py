"""Sample Python file demonstrating that early returns inside a with-statement are safe.

Context managers guarantee that __exit__() executes upon returning from within the block.
"""


def parse_line_or_default(filepath: str, default_val: str) -> str:
    """Safe function: early return inside with-block still triggers __exit__()."""
    with open(filepath, "r") as f:
        line = f.readline()
        if not line:
            return default_val
        return line.strip()


if __name__ == "__main__":
    pass
