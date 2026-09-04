"""Unknown Case: Helper in same module closes resource conditionally."""


def maybe_close(handle, should_close: bool):
    if should_close:
        handle.close()


def process_with_maybe_close():
    f = open("data.bin", "rb")
    # Proof fails because callee cleanup is not guaranteed on all execution paths
    maybe_close(f, True)
    return "transferred"
