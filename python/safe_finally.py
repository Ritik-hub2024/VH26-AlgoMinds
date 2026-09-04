"""Sample Python file demonstrating safe cleanup using try...finally.

In this scenario, even though an exception path returns early inside the except handler,
the finally block is guaranteed by Python runtime to execute before exiting the scope,
ensuring f.close() is always called and no resource is leaked.
"""


def parse_record_safe_finally(filename: str) -> str:
    """Guaranteed safe: finally block ensures f.close() runs even on exception returns."""
    f = open(filename, "r")
    try:
        raw = f.read()
        if not raw:
            raise ValueError("File is empty")
        return raw.strip()
    except ValueError:
        return "DEFAULT_RECORD"
    finally:
        f.close()
