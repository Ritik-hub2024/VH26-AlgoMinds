"""Test case: File opened and returned without closing."""

def process_data(filename: str):
    f = open(filename, "r")
    data = f.read()
    return data
