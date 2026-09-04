"""Test case: Safe reassignment where handle is closed before being reassigned."""

def process_safely():
    f = open("log.txt", "w")
    f.close()
    f = open("data.txt", "w")
    f.close()
