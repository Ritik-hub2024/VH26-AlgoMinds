"""Sample Python file demonstrating an asymmetrical branch leak.

f is opened before an if/else construct; the if branch calls close(), but the else
branch returns early without closing the file handle.
"""


def process_with_branch(filename: str, fast_mode: bool) -> str:
    """Leaking function: else branch returns early without closing f."""
    f = open(filename, "r")

    if fast_mode:
        data = f.read(100)
        f.close()
        return data
    else:
        # Leak! Early return without calling f.close()
        return "SLOW_MODE_NOT_SUPPORTED"


if __name__ == "__main__":
    pass
