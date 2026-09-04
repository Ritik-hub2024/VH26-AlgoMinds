"""JSON reporter for machine-readable analysis results."""

import json
import sys
from typing import TextIO, Optional
from models.report import AnalysisReport


class JSONReporter:
    """Formats analysis report into structured JSON."""

    def __init__(self, stream: TextIO = sys.stdout, indent: int = 2) -> None:
        self.stream = stream
        self.indent = indent

    def to_json(self, report: AnalysisReport) -> str:
        """Convert report to JSON string."""
        return json.dumps(report.to_dict(), indent=self.indent)

    def report(self, report: AnalysisReport) -> None:
        """Write JSON report to output stream."""
        self.stream.write(self.to_json(report))
        self.stream.write("\n")
