"""Tests for LeakGuard data models."""

import unittest
from models.location import SourceLocation
from models.issue import Severity, LeakIssue
from models.report import SyntaxErrorInfo, ParseResult, AnalysisReport


class TestModels(unittest.TestCase):
    """Test data model instantiation, serialization, and properties."""

    def test_source_location(self):
        loc = SourceLocation(
            file_path="main.py",
            line=10,
            column=4,
            end_line=10,
            end_column=20,
        )
        self.assertEqual(loc.file_path, "main.py")
        self.assertEqual(loc.line, 10)
        self.assertEqual(str(loc), "main.py:10:4-10:20")

        d = loc.to_dict()
        self.assertEqual(d["file_path"], "main.py")
        self.assertEqual(d["line"], 10)
        self.assertEqual(d["column"], 4)

    def test_leak_issue(self):
        loc = SourceLocation(file_path="test.py", line=5, column=0)
        issue = LeakIssue(
            rule_id="LEAK001",
            message="Unclosed resource",
            severity=Severity.HIGH,
            location=loc,
            recommendation="Use with statement",
        )
        self.assertEqual(issue.rule_id, "LEAK001")
        self.assertEqual(issue.severity, Severity.HIGH)
        d = issue.to_dict()
        self.assertEqual(d["rule_id"], "LEAK001")
        self.assertEqual(d["severity"], "HIGH")
        self.assertEqual(d["location"]["line"], 5)

    def test_syntax_error_info(self):
        err = SyntaxErrorInfo(
            message="invalid syntax",
            filename="broken.py",
            line=12,
            column=8,
            text="return 1 +",
        )
        self.assertEqual(err.line, 12)
        self.assertIn("broken.py:12:8", str(err))
        d = err.to_dict()
        self.assertEqual(d["message"], "invalid syntax")
        self.assertEqual(d["text"], "return 1 +")

    def test_analysis_report_metrics(self):
        report = AnalysisReport(target_path="src/", files_scanned=2)
        self.assertFalse(report.has_errors_or_issues)
        self.assertEqual(report.clean_files_count, 2)

        err = SyntaxErrorInfo(message="error", filename="a.py", line=1, column=1)
        report.syntax_errors.append(err)
        self.assertTrue(report.has_errors_or_issues)
        self.assertEqual(report.clean_files_count, 1)

        d = report.to_dict()
        self.assertEqual(d["summary"]["files_scanned"], 2)
        self.assertEqual(d["summary"]["syntax_errors_count"], 1)


if __name__ == "__main__":
    unittest.main()
