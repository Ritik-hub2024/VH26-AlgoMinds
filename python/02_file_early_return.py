"""Sample 02: Resource leak due to early return before close().

Pattern: open -> if condition -> return -> close
"""


def parse_header_or_skip(filename: str, skip: bool) -> str:
    """Leaking function: early return skips close() call when skip is True."""
    f = open(filename, "r")

    if skip:
        # Leak! Returns without closing 'f'
        return "SKIPPED"

    header = f.readline()
    f.close()
    return header


if __name__ == "__main__":
    pass
