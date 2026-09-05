"""PR Security Gate Demo Candidate - Unclosed Leak."""


def process_report():
    f = open("report.csv")
    return f.read()
