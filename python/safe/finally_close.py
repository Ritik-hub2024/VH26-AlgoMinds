"""Sample showing safe resource cleanup guaranteed by finally block."""


def load_data(filename: str = "data.txt"):
    f = open(filename)
    try:
        return f.read()
    finally:
        f.close()
