"""Leak Case: Resource closed in one branch but unclosed in the other."""


def process_by_mode(mode: str):
    f = open("data.log", "r")
    if mode == "immediate":
        f.close()
        return "immediate_done"
    else:
        # LEAK: falls through and returns without closing f
        return "deferred_pending"
