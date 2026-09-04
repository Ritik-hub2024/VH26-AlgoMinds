"""Test case: Returned resource where handle escapes caller scope."""

def create_stream():
    f = open("stream.bin", "rb")
    return f  # Resource returned to caller; local analyzer cannot verify consumer closure
