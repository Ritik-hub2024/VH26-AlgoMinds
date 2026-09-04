"""Test case: Argument transfer where resource escapes into an external/unprovable function."""

def external_consumer(h):
    # Does not close h
    pass

def pass_argument():
    f = open("transfer.txt", "r")
    external_consumer(f)  # Ownership transferred; callee does not close it
