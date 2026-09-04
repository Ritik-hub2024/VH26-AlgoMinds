"""Sample showing safe cleanup when exceptions are handled and finally ensures close()."""


def load_data(filename: str = "data.txt"):
    f = open(filename)
    try:
        risky_operation()
    except Exception:
        handle_error()
    finally:
        f.close()


def risky_operation():
    pass


def handle_error():
    pass
