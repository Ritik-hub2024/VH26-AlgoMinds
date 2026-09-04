"""Safe Case: Multiple resources managed in a single with statement."""


def copy_files():
    with open("source.txt", "r") as src, open("dest.txt", "w") as dst:
        data = src.read()
        dst.write(data)
    # SAFE: both src and dst exit context automatically
    return len(data)
