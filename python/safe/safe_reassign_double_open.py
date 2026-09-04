"""Adversarial Safe Case: Sequential acquisition and release with variable reuse."""


def transform_pipeline():
    # First resource safely closed
    f = open("input.raw", "r")
    raw = f.read()
    f.close()

    # Variable reused for second resource, also safely closed
    f = open("output.cleaned", "w")
    f.write(raw.strip())
    f.close()

    return True
