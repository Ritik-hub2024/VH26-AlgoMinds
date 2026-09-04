"""Leak Case: Early exit from loop skips subsequent cleanup."""


def scan_entries(targets):
    f = open("audit.log", "a")
    for item in targets:
        if item == "HALT":
            return -1  # LEAK: early return skips f.close()
        f.write(f"{item}\n")
    f.close()
    return 0
