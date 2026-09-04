"""Adversarial Leak Case: Error handler catches exception and returns before close."""


def read_metrics_adversarial():
    f = open("metrics.json", "r")
    try:
        data = f.read()
        val = int(data)
    except ValueError:
        return -1  # LEAK: exception handler returns without closing f
    f.close()
    return val
