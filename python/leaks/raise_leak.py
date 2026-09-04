"""Sample showing resource leak when raise terminates execution before close()."""


def load_data(filename: str = "data.txt"):
    f = open(filename)
    raise RuntimeError("failure")
    f.close()
