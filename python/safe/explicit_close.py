"""Test case: File opened and explicitly closed."""

def load_data_safely(filename: str):
    f = open(filename, "r")
    data = f.read()
    f.close()
    return data
