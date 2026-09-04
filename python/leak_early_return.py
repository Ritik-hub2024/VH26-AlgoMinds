"""Sample Python file demonstrating a resource leak due to an early return.

open() is called and f.close() exists at the end, but an intervening branch
can return early without closing the file handle.
"""


def parse_header_or_skip(filename: str, skip: bool) -> str:
    """Leaking function: early return skips close() call."""
    f = open(filename, "r")

    if skip:
        # Leak! Returns without closing 'f'
        return "SKIPPED"

    header = f.readline()
    f.close()
    return header
