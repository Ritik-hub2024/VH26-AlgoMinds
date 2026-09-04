"""Test case: Reassignment leak where previous resource handle is overwritten without closing."""

def process_data():
    f = open("log.txt", "w")
    f = open("data.txt", "w")  # Overwrites first open handle without closing
    f.close()
