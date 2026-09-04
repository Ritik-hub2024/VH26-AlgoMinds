"""Leak Case: Early exit in nested try-except bypasses cleanup."""


def parse_nested_payload():
    f = open("payload.dat", "rb")
    try:
        try:
            val = int(f.readline())
            if val < 0:
                raise ValueError("Negative payload")
        except ValueError:
            return None  # LEAK: inner exception returns early before f.close()
    finally:
        pass
    f.close()
    return val
