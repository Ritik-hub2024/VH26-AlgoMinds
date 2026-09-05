"""PR Security Gate Demo Candidate - Remediated with Context Manager."""


def process_report():
    with open("report.csv") as f:
        return f.read()
