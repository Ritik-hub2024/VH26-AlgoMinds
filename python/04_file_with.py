"""Sample 04: Safe file handling using context manager (with open)."""


def read_config_with(path: str) -> str:
    """Safe function: with open(...) guarantees resource cleanup via __exit__."""
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


if __name__ == "__main__":
    pass
