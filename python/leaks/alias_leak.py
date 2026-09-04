"""Test case: Alias leak where resource is aliased but neither handle is closed."""

def leak_alias():
    f = open("report.csv", "r")
    g = f
    return 42  # Neither f nor g was closed
