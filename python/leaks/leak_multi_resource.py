"""Leak Case: Multiple resources allocated, but one is never closed."""


def sync_records():
    src = open("source.csv", "r")
    dst = open("dest.csv", "w")
    content = src.read()
    dst.write(content)
    src.close()
    # LEAK: dst is never closed before return
    return True
