"""Test case: Safe aliasing where alias handle g is closed, releasing underlying resource f."""

def alias_safe():
    f = open("data.txt", "r")
    g = f
    g.close()  # Closing alias correctly frees the underlying resource
