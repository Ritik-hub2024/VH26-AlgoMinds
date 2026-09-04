"""Adversarial Safe Case: Early return inside context manager is guaranteed safe."""


def query_document(user_id: int):
    with open("documents.json", "r") as f:
        if user_id <= 0:
            return None  # SAFE: with statement guarantees __exit__ runs
        return f.read()
