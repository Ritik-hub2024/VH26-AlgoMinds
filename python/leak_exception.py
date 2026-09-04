"""Sample Python file demonstrating an exception path resource leak.

In this scenario, a file resource is opened and subsequently read within a try block.
If an exception occurs (e.g. ValueError), the exception handler returns early without
closing the resource. On the normal path, f.close() is called before returning.
Since there is no finally block guaranteeing cleanup, the file descriptor leaks on the
exception path.
"""


def parse_record_with_exception_leak(filename: str) -> str:
    """Demonstrates a file resource leak where an exception path returns before close()."""
    f = open(filename, "r")
    try:
        raw = f.read()
        if not raw:
            raise ValueError("File is empty")
    except ValueError:
        # Leak: exception handler returns without closing 'f'
        return "DEFAULT_RECORD"
    f.close()
    return raw.strip()
