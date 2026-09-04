"""Tests for LeakGuard CLI scanning functionality."""

import io
import tempfile
import unittest
from pathlib import Path
from cli import scan_target, discover_python_files
from reporter.console import ConsoleReporter


class TestCLI(unittest.TestCase):
    """Test CLI file discovery, directory scanning, and actionable report generation."""

    def test_discover_python_files(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            f1 = tmp_path / "a.py"
            f2 = tmp_path / "b.py"
            f3 = tmp_path / "c.txt"
            sub = tmp_path / "sub"
            sub.mkdir()
            f4 = sub / "d.py"

            f1.write_text("x = 1")
            f2.write_text("y = 2")
            f3.write_text("text")
            f4.write_text("z = 3")

            py_files = discover_python_files(tmp_path)
            self.assertEqual(len(py_files), 3)
            file_names = {p.name for p in py_files}
            self.assertEqual(file_names, {"a.py", "b.py", "d.py"})

    def test_scan_python_directory(self):
        python_dir = Path(__file__).resolve().parent.parent / "python"
        report = scan_target(str(python_dir))

        # 11 files in python/:
        # 6 Safe (04_file_with, 10_normal_close, safe_file, safe_try_finally, safe_with, safe_with_early_return)
        # 5 Leak (01_file_no_close, 02_file_early_return, leak_file, leak_early_return, leak_if_else)
        self.assertGreaterEqual(report.files_scanned, 11)
        self.assertGreaterEqual(len(report.issues), 5)
        self.assertEqual(len(report.syntax_errors), 1)
        self.assertIn("invalid_python.py", report.syntax_errors[0].filename)
        self.assertGreaterEqual(report.clean_files_count, 6)

    def test_scan_examples_directory(self):
        examples_dir = Path(__file__).resolve().parent.parent / "examples"
        report = scan_target(str(examples_dir))

        self.assertEqual(report.files_scanned, 3)
        # 1 syntax error (invalid_syntax_sample.py)
        self.assertEqual(len(report.syntax_errors), 1)
        self.assertEqual(
            report.syntax_errors[0].filename,
            str((examples_dir / "invalid_syntax_sample.py").resolve()),
        )

    def test_actionable_cli_report_output(self):
        """Verify that CLI output contains File, Line, Resource, Problem, Leak Path, Recommendation."""
        python_dir = Path(__file__).resolve().parent.parent / "python"
        target_file = python_dir / "leak_early_return.py"
        report = scan_target(str(target_file))

        buf = io.StringIO()
        reporter = ConsoleReporter(stream=buf, use_color=False)
        reporter.report(report)
        output = buf.getvalue()

        # All 6 required fields must appear in the CLI output
        self.assertIn("File:", output)
        self.assertIn("Line:", output)
        self.assertIn("Resource:", output)
        self.assertIn("Problem:", output)
        self.assertIn("Leak Path:", output)
        self.assertIn("Recommendation:", output)

        # Content assertions
        self.assertIn("leak_early_return.py", output)
        self.assertIn("f (type: file)", output)
        self.assertIn("L10: open() -> L12: if skip -> L14: return (leak)", output)
        self.assertIn("with open", output)


if __name__ == "__main__":
    unittest.main()
