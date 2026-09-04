"""Sample 10: Normal safe file resource pattern (open followed by close)."""


def process_file(path: str) -> str:
    """Opens a file and explicitly closes it -> SAFE."""
    f = open(path, "r", encoding="utf-8")
    data = f.read()
    f.close()
    return data


if __name__ == "__main__":
    pass
