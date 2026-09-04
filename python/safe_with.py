"""Sample Python file demonstrating safe resource handling via context manager."""


def read_data_with(filename: str) -> str:
    """Safe function: with open(...) automatically guarantees resource closure."""
    with open(filename, "r", encoding="utf-8") as f:
        data = f.read()
        return data


if __name__ == "__main__":
    pass
