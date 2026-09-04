"""Leak Case: Early return inside nested conditional branch."""


def process_nested_config(env: str, debug: bool):
    f = open("config.json", "r")
    if env == "production":
        if not debug:
            return "production-fast-path"  # LEAK: early return without closing f
    data = f.read()
    f.close()
    return data
