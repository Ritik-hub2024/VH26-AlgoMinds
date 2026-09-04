"""Safe Case: Outer try...finally guarantees cleanup around nested blocks."""


def safe_nested_processing():
    f = open("records.csv", "r")
    try:
        try:
            line = f.readline()
            val = int(line)
        except ValueError:
            val = 0
        return val
    finally:
        f.close()
