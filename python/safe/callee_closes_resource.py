"""Test case: Callee proof where resource is passed to a same-module function that unconditionally closes it."""

def close_resource(handle):
    handle.close()

def caller_safe():
    f = open("callee_closed.txt", "w")
    close_resource(f)
