"""Sample showing resource leak when exception handler returns before close()."""


def load_data(filename: str = "data.txt"):
    f = open(filename)
    try:
        risky_operation()
    except Exception:
        return None
    f.close()


def risky_operation():
    pass
