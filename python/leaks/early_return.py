"""Test case: File opened, early return in if branch before close."""

def parse_with_condition(filename: str, skip: bool):
    f = open(filename, "r")
    if skip:
        return ""
    content = f.read()
    f.close()
    return content
