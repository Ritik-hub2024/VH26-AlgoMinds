"""Test case: Collection escape where resource is appended into a container."""

def store_in_list():
    resources = []
    f = open("pooled.txt", "w")
    resources.append(f)  # Container escape
