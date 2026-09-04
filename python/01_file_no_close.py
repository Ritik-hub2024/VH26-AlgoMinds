"""Sample 01: Unclosed file resource leak (open without close)."""


def load_data(path: str) -> str:
    """Opens a file but never closes it -> LEAK."""
    f = open(path, "r")
    data = f.read()
    return data


if __name__ == "__main__":
    pass
