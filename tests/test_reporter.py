"""Tests for ConsoleReporter and JSONReporter."""

import io
import json
import unittest
from models.report import AnalysisReport, SyntaxErrorInfo
from reporter.console import ConsoleReporter
from reporter.json_reporter import JSONReporter


class TestReporters(unittest.TestCase):
    """Test console and JSON reporters."""

    def test_console_reporter_output(self):
        buf = io.StringIO()
        reporter = ConsoleReporter(stream=buf, use_color=False)

        report = AnalysisReport(target_path="sample/", files_scanned=2)
        err = SyntaxErrorInfo(
            message="invalid syntax",
            filename="bad.py",
            line=4,
            column=10,
            text="foo(",
        )
        report.syntax_errors.append(err)

        reporter.report(report)
        output = buf.getvalue()

        self.assertIn("LeakGuard Static Analysis Report", output)
        self.assertIn("sample/", output)
        self.assertIn("bad.py:4:10", output)
        self.assertIn("FAILED", output)

    def test_json_reporter_output(self):
        buf = io.StringIO()
        reporter = JSONReporter(stream=buf)

        report = AnalysisReport(target_path="sample/", files_scanned=1)
        reporter.report(report)

        output = buf.getvalue()
        data = json.loads(output)

        self.assertEqual(data["target_path"], "sample/")
        self.assertEqual(data["summary"]["files_scanned"], 1)
        self.assertEqual(data["summary"]["syntax_errors_count"], 0)


if __name__ == "__main__":
    unittest.main()
