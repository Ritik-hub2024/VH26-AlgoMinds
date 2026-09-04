"""Test case: Attribute storage where resource is stored on an object."""

class ResourceHolder:
    def __init__(self):
        self.handle = open("member.dat", "w")  # Stored on object attribute
