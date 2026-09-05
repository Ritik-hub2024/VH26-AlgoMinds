"""PR Security Gate Demo Fixture - Unclosed Leak."""


def read_data():
    f = open("data.txt")
    return f.read()
